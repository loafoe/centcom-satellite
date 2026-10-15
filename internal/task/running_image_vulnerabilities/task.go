// Package running_image_vulnerabilities reports Amazon Inspector findings for
// the container images actually running in this cluster, as opposed to every
// image stored in ECR (where most findings live on images nothing runs).
//
// How it gets there:
//
//  1. List the cluster's pods and take each container's imageID digest
//     (only images from ECR in the satellite's own region; other registries
//     are counted in coverage, Inspector does not scan them).
//  2. Resolve each digest through ECR: a multi-arch image index is replaced
//     by its per-platform manifests, because that is what Inspector scans —
//     a pod reports the index digest, which never matches a finding.
//  3. Read each platform image's Inspector coverage status. Images whose
//     scan eligibility expired (e.g. not pulled within the account's
//     Inspector pull-date rescan window) have no active findings and are
//     reported as a coverage gap rather than as clean. (ECR DescribeImages
//     does not report scan status for Inspector-scanned images.)
//  4. Page Inspector ListFindings for the platform images (at most 10
//     values per filter, an API limit for both calls) and aggregate
//     client-side by vulnerability, package or image. Inspector's own aggregations cannot
//     be restricted to a set of images, so they are not used for this.
//
// The scan runs under TimeBudget, inside the satellite's 60s HTTP write
// timeout; when the budget runs out the result is partial
// (Complete=false, StopReason=time_budget), never an error.
package running_image_vulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"k8s.io/client-go/kubernetes"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "running_image_vulnerabilities"

const (
	// TimeBudget keeps a scan well inside the satellite's 60s HTTP write
	// timeout (same budget as the CloudTrail tasks).
	TimeBudget   = 45 * time.Second
	defaultLimit = 50
	maxLimit     = 500
	// maxListed caps the per-group example lists (workloads, packages,
	// vulnerability IDs) so one widespread CVE can't blow up the response.
	maxListed = 10
)

// Group-by values.
const (
	GroupByVulnerability = "VULNERABILITY"
	GroupByPackage       = "PACKAGE"
	GroupByImage         = "IMAGE"
)

var validSeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true, "UNTRIAGED": true}

// Payload for running_image_vulnerabilities.
type Payload struct {
	Region string `json:"region,omitempty"`
	// Namespaces limits the scan to pods in these namespaces; empty = all.
	Namespaces []string `json:"namespaces,omitempty"`
	// Severities to include (Inspector labels); default ["CRITICAL"].
	Severities []string `json:"severities,omitempty"`
	// FixAvailable keeps findings with this Inspector fixAvailable value:
	// YES, NO or PARTIAL. Empty = any.
	FixAvailable string `json:"fix_available,omitempty"`
	// ExploitAvailable keeps findings with this exploitAvailable value:
	// YES or NO. Empty = any.
	ExploitAvailable string `json:"exploit_available,omitempty"`
	// GroupBy: VULNERABILITY (default), PACKAGE or IMAGE.
	GroupBy string `json:"group_by,omitempty"`
	// Limit caps the number of groups returned (default 50, max 500);
	// totals and coverage always cover everything scanned.
	Limit int `json:"limit,omitempty"`
}

// Coverage says how much of what runs could actually be assessed — read it
// before trusting a low finding count.
type Coverage struct {
	RunningContainers int `json:"running_containers"`
	// RunningImages is the number of distinct image digests running.
	RunningImages int `json:"running_images"`
	// ECRImages are running images from this account's ECR in this region;
	// OtherRegistry are the rest (other registries, accounts or regions —
	// not assessed).
	ECRImages           int      `json:"ecr_images"`
	OtherRegistryImages int      `json:"other_registry_images"`
	OtherRegistries     []string `json:"other_registries,omitempty"`
	// UnresolvedImages could not be looked up in ECR (deleted, or another
	// account's registry without access).
	UnresolvedImages int `json:"unresolved_images"`
	// PlatformImages are the per-platform manifests Inspector scans (an
	// image index counts once per platform).
	PlatformImages int `json:"platform_images"`
	// ScanStatus counts platform images by Inspector coverage status
	// ("ACTIVE", "INACTIVE/<reason>", "NOT_COVERED").
	ScanStatus map[string]int `json:"scan_status"`
	// AssessedImages are running images with at least one platform image
	// Inspector currently has findings for; UnscannedImages are resolved
	// images with none (e.g. scan eligibility expired) — their findings
	// are unknown, not zero. ImagesWithFindings matched the filter.
	AssessedImages     int `json:"assessed_images"`
	UnscannedImages    int `json:"unscanned_images"`
	ImagesWithFindings int `json:"images_with_findings"`
}

// PackageFix is a vulnerable package version and the version that fixes it.
type PackageFix struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	FixedInVersion string `json:"fixed_in_version,omitempty"`
}

// Group is one row of the aggregated result.
type Group struct {
	Key   string `json:"key"`
	Title string `json:"title,omitempty"`
	// Severity is the highest severity among the group's findings.
	Severity       string         `json:"severity"`
	Findings       int            `json:"findings"`
	SeverityCounts map[string]int `json:"severity_counts"`
	// Images is the number of distinct running images affected.
	Images int `json:"images"`
	// Vulnerabilities is the number of distinct vulnerability IDs.
	Vulnerabilities  int          `json:"vulnerabilities"`
	VulnerabilityIDs []string     `json:"vulnerability_ids,omitempty"`
	Packages         []PackageFix `json:"packages,omitempty"`
	// FixAvailable / ExploitAvailable are set for VULNERABILITY groups.
	FixAvailable     string  `json:"fix_available,omitempty"`
	ExploitAvailable string  `json:"exploit_available,omitempty"`
	EPSS             float64 `json:"epss,omitempty"`
	// Workloads are namespace/Kind/name of the workloads running affected
	// images (first maxListed), WorkloadsTotal the full count.
	Workloads      []string `json:"workloads,omitempty"`
	WorkloadsTotal int      `json:"workloads_total"`
}

// Report is the task result payload.
type Report struct {
	Region           string         `json:"region"`
	AccountID        string         `json:"account_id"`
	Severities       []string       `json:"severities"`
	FixAvailable     string         `json:"fix_available,omitempty"`
	ExploitAvailable string         `json:"exploit_available,omitempty"`
	GroupBy          string         `json:"group_by"`
	Coverage         Coverage       `json:"coverage"`
	TotalFindings    int            `json:"total_findings"`
	SeverityCounts   map[string]int `json:"severity_counts"`
	GroupsTotal      int            `json:"groups_total"`
	Groups           []Group        `json:"groups"`
	Complete         bool           `json:"complete"`
	StopReason       string         `json:"stop_reason,omitempty"`
	ECRCalls         int            `json:"ecr_calls"`
	InspectorCalls   int            `json:"inspector_calls"`
}

type ecrAPI interface {
	BatchGetImage(context.Context, *ecr.BatchGetImageInput, ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error)
}

type inspectorAPI interface {
	ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
	ListCoverage(context.Context, *inspector2.ListCoverageInput, ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error)
}

// Task implements running_image_vulnerabilities.
type Task struct {
	clientset kubernetes.Interface
	// clients returns the ECR and Inspector clients plus the region they
	// resolved to and the caller's account: only images in that account's
	// ECR in that region are assessed (Inspector only scans its own
	// account's images; e.g. EKS add-on images live in AWS-owned registries).
	clients func(ctx context.Context, region string) (ecrAPI, inspectorAPI, string, string, error)
	budget  time.Duration
}

func New(clientset kubernetes.Interface) *Task {
	return &Task{
		clientset: clientset,
		clients: func(ctx context.Context, region string) (ecrAPI, inspectorAPI, string, string, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, nil, "", "", err
			}
			id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return nil, nil, "", "", fmt.Errorf("get caller identity: %w", err)
			}
			return ecr.NewFromConfig(cfg), inspector2.NewFromConfig(cfg), cfg.Region, aws.ToString(id.Account), nil
		},
		budget: TimeBudget,
	}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var p Payload
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &p); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	if msg := normalize(&p); msg != "" {
		return task.NewErrorResult(msg), nil
	}

	ecrClient, inspClient, region, account, err := t.clients(ctx, p.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build AWS clients: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, t.budget)
	defer cancel()

	s := &scan{payload: p, region: region, account: account, ecr: ecrClient, insp: inspClient}
	s.report = Report{
		Region: region, AccountID: account, Severities: p.Severities, FixAvailable: p.FixAvailable,
		ExploitAvailable: p.ExploitAvailable, GroupBy: p.GroupBy,
		Coverage:       Coverage{ScanStatus: map[string]int{}},
		SeverityCounts: map[string]int{}, Groups: []Group{}, Complete: true,
	}

	if err := s.collectPods(ctx, t.clientset); err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	if err := s.resolveImages(ctx); err != nil {
		return s.partialOrError(err)
	}
	if err := s.queryFindings(ctx); err != nil {
		return s.partialOrError(err)
	}
	return s.result(), nil
}

// partialOrError turns a budget/cancellation stop into a partial result and
// anything else into an error.
func (s *scan) partialOrError(err error) (*task.Result, error) {
	if s.stopped {
		return s.result(), nil
	}
	return nil, err
}

func (s *scan) result() *task.Result {
	s.finish()
	r := s.report
	msg := fmt.Sprintf("%d findings on %d of %d running images (%s, region %s)",
		r.TotalFindings, r.Coverage.ImagesWithFindings, r.Coverage.RunningImages, strings.Join(r.Severities, "/"), r.Region)
	if !r.Complete {
		msg += " — partial: " + r.StopReason
	}
	return task.NewSuccessResultWithDetails(msg, r)
}

// normalize applies defaults and validates p, returning a user-facing error
// message or "".
func normalize(p *Payload) string {
	if len(p.Severities) == 0 {
		p.Severities = []string{"CRITICAL"}
	}
	for i, sev := range p.Severities {
		p.Severities[i] = strings.ToUpper(sev)
		if !validSeverities[p.Severities[i]] {
			return fmt.Sprintf("invalid severity %q (allowed: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNTRIAGED)", sev)
		}
	}
	p.FixAvailable = strings.ToUpper(p.FixAvailable)
	if p.FixAvailable != "" && p.FixAvailable != "YES" && p.FixAvailable != "NO" && p.FixAvailable != "PARTIAL" {
		return fmt.Sprintf("invalid fix_available %q (allowed: YES, NO, PARTIAL)", p.FixAvailable)
	}
	p.ExploitAvailable = strings.ToUpper(p.ExploitAvailable)
	if p.ExploitAvailable != "" && p.ExploitAvailable != "YES" && p.ExploitAvailable != "NO" {
		return fmt.Sprintf("invalid exploit_available %q (allowed: YES, NO)", p.ExploitAvailable)
	}
	p.GroupBy = strings.ToUpper(p.GroupBy)
	if p.GroupBy == "" {
		p.GroupBy = GroupByVulnerability
	}
	if p.GroupBy != GroupByVulnerability && p.GroupBy != GroupByPackage && p.GroupBy != GroupByImage {
		return fmt.Sprintf("invalid group_by %q (allowed: VULNERABILITY, PACKAGE, IMAGE)", p.GroupBy)
	}
	if p.Limit <= 0 {
		p.Limit = defaultLimit
	}
	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}
	return ""
}
