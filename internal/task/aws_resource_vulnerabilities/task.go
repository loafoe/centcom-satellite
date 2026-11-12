// Package aws_resource_vulnerabilities reports Amazon Inspector package and
// code vulnerability findings for this account's EC2 instances or Lambda
// functions in the satellite's region, grouped both by vulnerability and by
// resource from one scan.
//
// How it gets there:
//
//  1. ListCoverage for the resource type: every resource Inspector knows
//     about, with its scan status and metadata (tags, platform, AMI;
//     function name, runtime, layers).
//  2. ListFindings in batches of 10 resource IDs (an API limit) across
//     workers, so one heavily affected resource doesn't serialize the
//     whole scan behind its pagination.
//
// Network reachability findings are not vulnerabilities and are skipped.
// The scan runs under TimeBudget; when it runs out the result is partial
// (Complete=false, StopReason=time_budget), never an error.
package aws_resource_vulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "aws_resource_vulnerabilities"

const (
	TimeBudget       = 45 * time.Second
	defaultLimit     = 500
	maxLimit         = 2000
	defaultListLimit = 50
	maxListLimit     = 1000
	maxDescription   = 1000
	maxReferences    = 5
	maxTags          = 40
)

// Resource types (Inspector's names).
const (
	ResourceEC2    = "AWS_EC2_INSTANCE"
	ResourceLambda = "AWS_LAMBDA_FUNCTION"
)

var resourceAliases = map[string]string{
	"AWS_EC2_INSTANCE": ResourceEC2, "EC2": ResourceEC2, "AWSEC2INSTANCE": ResourceEC2,
	"AWS_LAMBDA_FUNCTION": ResourceLambda, "LAMBDA": ResourceLambda, "AWSLAMBDAFUNCTION": ResourceLambda,
}

var validSeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true, "UNTRIAGED": true}

// Payload for aws_resource_vulnerabilities.
type Payload struct {
	Region string `json:"region,omitempty"`
	// ResourceType: AWS_EC2_INSTANCE or AWS_LAMBDA_FUNCTION (also accepts
	// EC2/LAMBDA and Security Hub's AwsEc2Instance/AwsLambdaFunction).
	ResourceType string `json:"resource_type"`
	// Severities to include (Inspector labels); default ["CRITICAL"].
	Severities []string `json:"severities,omitempty"`
	// FixAvailable: YES, NO or PARTIAL; empty = any.
	FixAvailable string `json:"fix_available,omitempty"`
	// ExploitAvailable: YES or NO; empty = any.
	ExploitAvailable string `json:"exploit_available,omitempty"`
	// Limit caps the vulnerabilities and resources lists (each; default
	// 500, max 2000). Totals always cover everything scanned.
	Limit int `json:"limit,omitempty"`
	// ListLimit caps per-entry lists (resource IDs per vulnerability,
	// vulnerability IDs per resource, packages; default 50, max 1000).
	ListLimit int `json:"list_limit,omitempty"`
}

// Package is one vulnerable package as installed and the version fixing it.
type Package struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	FixedInVersion string `json:"fixed_in_version,omitempty"`
	PackageManager string `json:"package_manager,omitempty"`
	FilePath       string `json:"file_path,omitempty"`
	SourceLayer    string `json:"source_layer,omitempty"`
}

// Vulnerability is one vulnerability (CVE/GHSA/code rule) across resources.
type Vulnerability struct {
	ID       string `json:"id"`
	Title    string `json:"title,omitempty"`
	Type     string `json:"type"` // PACKAGE_VULNERABILITY or CODE_VULNERABILITY
	Severity string `json:"severity"`
	// CVSS is the highest base score across every source; EPSS the highest
	// probability; InspectorScore Inspector's own (environment-adjusted).
	CVSS               float64   `json:"cvss,omitempty"`
	EPSS               float64   `json:"epss,omitempty"`
	InspectorScore     float64   `json:"inspector_score,omitempty"`
	FixAvailable       string    `json:"fix_available,omitempty"`
	ExploitAvailable   string    `json:"exploit_available,omitempty"`
	LastKnownExploitAt string    `json:"last_known_exploit_at,omitempty"`
	VendorSeverity     string    `json:"vendor_severity,omitempty"`
	Findings           int       `json:"findings"`
	Resources          int       `json:"resources"`
	ResourceIDs        []string  `json:"resource_ids,omitempty"`
	Packages           []Package `json:"packages,omitempty"`
	Description        string    `json:"description,omitempty"`
	Remediation        string    `json:"remediation,omitempty"`
	SourceURL          string    `json:"source_url,omitempty"`
	ReferenceURLs      []string  `json:"reference_urls,omitempty"`
	CWEs               []string  `json:"cwes,omitempty"`
	Detector           string    `json:"detector,omitempty"`
	FirstObservedAt    string    `json:"first_observed_at,omitempty"`
	LastObservedAt     string    `json:"last_observed_at,omitempty"`
}

// EC2Details describes an instance.
type EC2Details struct {
	InstanceType       string   `json:"instance_type,omitempty"`
	Platform           string   `json:"platform,omitempty"`
	ImageID            string   `json:"image_id,omitempty"`
	KeyName            string   `json:"key_name,omitempty"`
	VpcID              string   `json:"vpc_id,omitempty"`
	SubnetID           string   `json:"subnet_id,omitempty"`
	IamInstanceProfile string   `json:"iam_instance_profile,omitempty"`
	LaunchedAt         string   `json:"launched_at,omitempty"`
	IPv4Addresses      []string `json:"ipv4_addresses,omitempty"`
}

// LambdaDetails describes a function.
type LambdaDetails struct {
	FunctionName   string   `json:"function_name,omitempty"`
	Runtime        string   `json:"runtime,omitempty"`
	Version        string   `json:"version,omitempty"`
	PackageType    string   `json:"package_type,omitempty"`
	LastModifiedAt string   `json:"last_modified_at,omitempty"`
	ExecutionRole  string   `json:"execution_role,omitempty"`
	Architectures  []string `json:"architectures,omitempty"`
	Layers         []string `json:"layers,omitempty"`
}

// Resource is one affected EC2 instance or Lambda function.
type Resource struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Findings and SeverityCounts count this resource's matching findings;
	// Vulnerabilities the distinct vulnerability IDs among them, and
	// Fixable/Exploitable how many of those have a fix / known exploit.
	Findings         int            `json:"findings"`
	SeverityCounts   map[string]int `json:"severity_counts"`
	Vulnerabilities  int            `json:"vulnerabilities"`
	VulnerabilityIDs []string       `json:"vulnerability_ids,omitempty"`
	// VulnerabilityPackages are, per listed vulnerability ID, the packages
	// as installed on this resource (a CVE's Packages list is the union
	// across resources, which can name another OS's package).
	VulnerabilityPackages map[string][]Package `json:"vulnerability_packages,omitempty"`
	Fixable               int                  `json:"fixable"`
	Exploitable           int                  `json:"exploitable"`
	MaxCVSS               float64              `json:"max_cvss,omitempty"`
	MaxEPSS               float64              `json:"max_epss,omitempty"`
	ScanStatus            string               `json:"scan_status,omitempty"`
	ScanMode              string               `json:"scan_mode,omitempty"`
	LastScannedAt         string               `json:"last_scanned_at,omitempty"`
	Tags                  map[string]string    `json:"tags,omitempty"`
	EC2                   *EC2Details          `json:"ec2,omitempty"`
	Lambda                *LambdaDetails       `json:"lambda,omitempty"`
}

// Coverage says how much of this resource type Inspector actually assesses.
type Coverage struct {
	// Resources Inspector covers (any status); Scanned are ACTIVE,
	// NotScanned INACTIVE (stopped, unmanaged, eligibility expired, ...)
	// — their findings are unknown, not zero.
	Resources    int            `json:"resources"`
	Scanned      int            `json:"scanned"`
	NotScanned   int            `json:"not_scanned"`
	ScanStatus   map[string]int `json:"scan_status"`
	WithFindings int            `json:"with_findings"`
}

// Report is the task result payload.
type Report struct {
	Region               string          `json:"region"`
	AccountID            string          `json:"account_id"`
	ResourceType         string          `json:"resource_type"`
	Severities           []string        `json:"severities"`
	FixAvailable         string          `json:"fix_available,omitempty"`
	ExploitAvailable     string          `json:"exploit_available,omitempty"`
	Coverage             Coverage        `json:"coverage"`
	TotalFindings        int             `json:"total_findings"`
	SeverityCounts       map[string]int  `json:"severity_counts"`
	VulnerabilitiesTotal int             `json:"vulnerabilities_total"`
	Vulnerabilities      []Vulnerability `json:"vulnerabilities"`
	ResourcesTotal       int             `json:"resources_total"`
	Resources            []Resource      `json:"resources"`
	Complete             bool            `json:"complete"`
	StopReason           string          `json:"stop_reason,omitempty"`
	InspectorCalls       int             `json:"inspector_calls"`
}

type inspectorAPI interface {
	ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
	ListCoverage(context.Context, *inspector2.ListCoverageInput, ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error)
}

// Task implements aws_resource_vulnerabilities.
type Task struct {
	clients func(ctx context.Context, region string) (inspectorAPI, string, string, error)
	budget  time.Duration
}

func New() *Task {
	return &Task{
		clients: func(ctx context.Context, region string) (inspectorAPI, string, string, error) {
			cfg, err := awshelper.LoadConfig(ctx, awshelper.Options{Region: region})
			if err != nil {
				return nil, "", "", err
			}
			id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return nil, "", "", fmt.Errorf("get caller identity: %w", err)
			}
			return inspector2.NewFromConfig(cfg), cfg.Region, aws.ToString(id.Account), nil
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

	insp, region, account, err := t.clients(ctx, p.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to build AWS clients: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, t.budget)
	defer cancel()

	s := newScan(p, insp)
	s.report.Region, s.report.AccountID = region, account

	if err := s.collectCoverage(ctx); err != nil {
		return s.partialOrError(err)
	}
	if err := s.queryFindings(ctx); err != nil {
		return s.partialOrError(err)
	}
	return s.result(), nil
}

func (s *scan) partialOrError(err error) (*task.Result, error) {
	if s.stopped {
		return s.result(), nil
	}
	return awshelper.WrapError("aws resource vulnerabilities", err)
}

func (s *scan) result() *task.Result {
	s.finish()
	r := s.report
	msg := fmt.Sprintf("%d findings, %d vulnerabilities on %d of %d %s resources (%s, region %s)",
		r.TotalFindings, r.VulnerabilitiesTotal, r.Coverage.WithFindings, r.Coverage.Resources,
		r.ResourceType, strings.Join(r.Severities, "/"), r.Region)
	if !r.Complete {
		msg += " — partial: " + r.StopReason
	}
	return task.NewSuccessResultWithDetails(msg, r)
}

func normalize(p *Payload) string {
	key := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(p.ResourceType), "-", "_"))
	rt, ok := resourceAliases[key]
	if !ok {
		return fmt.Sprintf("invalid resource_type %q (allowed: AWS_EC2_INSTANCE, AWS_LAMBDA_FUNCTION)", p.ResourceType)
	}
	p.ResourceType = rt
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
	if p.Limit <= 0 {
		p.Limit = defaultLimit
	}
	p.Limit = min(p.Limit, maxLimit)
	if p.ListLimit <= 0 {
		p.ListLimit = defaultListLimit
	}
	p.ListLimit = min(p.ListLimit, maxListLimit)
	return ""
}
