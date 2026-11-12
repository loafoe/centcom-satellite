package aws_resource_vulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

const (
	// idsPerCall is Inspector's limit on values per string filter.
	idsPerCall = 10
	workers    = 8
)

var severityRank = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "UNTRIAGED": 0}

type vulnAcc struct {
	Vulnerability
	resources map[string]bool
	packages  map[Package]bool
	first     time.Time
	last      time.Time
}

type resAcc struct {
	Resource
	vulns       map[string]bool
	pkgs        map[string]map[Package]bool
	fixable     map[string]bool
	exploitable map[string]bool
	covered     bool
}

type scan struct {
	payload Payload
	insp    inspectorAPI

	mu        sync.Mutex
	resources map[string]*resAcc
	order     []string
	vulns     map[string]*vulnAcc
	report    Report
	stopped   bool
}

func newScan(p Payload, insp inspectorAPI) *scan {
	return &scan{
		payload: p, insp: insp,
		resources: map[string]*resAcc{}, vulns: map[string]*vulnAcc{},
		report: Report{
			ResourceType: p.ResourceType, Severities: p.Severities,
			FixAvailable: p.FixAvailable, ExploitAvailable: p.ExploitAvailable,
			Coverage:       Coverage{ScanStatus: map[string]int{}},
			SeverityCounts: map[string]int{}, Vulnerabilities: []Vulnerability{}, Resources: []Resource{},
			Complete: true,
		},
	}
}

func eq(v string) itypes.StringFilter {
	return itypes.StringFilter{Comparison: itypes.StringComparisonEquals, Value: aws.String(v)}
}

// spend is checked before every AWS call.
func (s *scan) spend(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		s.mu.Lock()
		s.stop()
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.report.InspectorCalls++
	s.mu.Unlock()
	return nil
}

func (s *scan) budgetErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		s.mu.Lock()
		s.stop()
		s.mu.Unlock()
		return true
	}
	return false
}

// stop must be called with mu held.
func (s *scan) stop() {
	s.stopped = true
	s.report.Complete = false
	s.report.StopReason = "time_budget"
}

// resource returns (creating if needed) the accumulator for id; mu held.
func (s *scan) resource(id string) *resAcc {
	r := s.resources[id]
	if r == nil {
		r = &resAcc{
			Resource: Resource{ID: id, SeverityCounts: map[string]int{}},
			vulns:    map[string]bool{}, fixable: map[string]bool{}, exploitable: map[string]bool{},
			pkgs: map[string]map[Package]bool{},
		}
		s.resources[id] = r
		s.order = append(s.order, id)
	}
	return r
}

// collectCoverage lists every resource of the type Inspector covers.
func (s *scan) collectCoverage(ctx context.Context) error {
	fc := &itypes.CoverageFilterCriteria{ResourceType: []itypes.CoverageStringFilter{{
		Comparison: itypes.CoverageStringComparisonEquals, Value: aws.String(s.payload.ResourceType),
	}}}
	var next *string
	for {
		if err := s.spend(ctx); err != nil {
			return err
		}
		out, err := s.insp.ListCoverage(ctx, &inspector2.ListCoverageInput{FilterCriteria: fc, MaxResults: aws.Int32(200), NextToken: next})
		if err != nil {
			if s.budgetErr(ctx, err) {
				return err
			}
			return fmt.Errorf("inspector list coverage: %w", err)
		}
		s.mu.Lock()
		for i := range out.CoveredResources {
			s.addCoverage(&out.CoveredResources[i])
		}
		s.mu.Unlock()
		if aws.ToString(out.NextToken) == "" {
			return nil
		}
		next = out.NextToken
	}
}

// addCoverage records one covered resource; mu held. A function can have
// one record per scan type (package, code): ACTIVE wins.
func (s *scan) addCoverage(c *itypes.CoveredResource) {
	id := aws.ToString(c.ResourceId)
	if id == "" {
		return
	}
	r := s.resource(id)
	status := "UNKNOWN"
	if c.ScanStatus != nil {
		status = string(c.ScanStatus.StatusCode)
		if c.ScanStatus.Reason != "" && c.ScanStatus.Reason != itypes.ScanStatusReasonSuccessful {
			status += "/" + string(c.ScanStatus.Reason)
		}
	}
	if !r.covered || (r.ScanStatus != "ACTIVE" && status == "ACTIVE") {
		r.ScanStatus = status
		r.ScanMode = string(c.ScanMode)
		if c.LastScannedAt != nil {
			r.LastScannedAt = c.LastScannedAt.UTC().Format(time.RFC3339)
		}
	}
	r.covered = true
	if m := c.ResourceMetadata; m != nil {
		if e := m.Ec2; e != nil {
			d := r.ec2()
			d.ImageID = first(d.ImageID, aws.ToString(e.AmiId))
			d.Platform = first(d.Platform, string(e.Platform))
			r.mergeTags(e.Tags)
		}
		if l := m.LambdaFunction; l != nil {
			d := r.lambda()
			d.FunctionName = first(d.FunctionName, aws.ToString(l.FunctionName))
			d.Runtime = first(d.Runtime, string(l.Runtime))
			if len(d.Layers) == 0 {
				d.Layers = l.Layers
			}
			r.mergeTags(l.FunctionTags)
		}
	}
}

func (r *resAcc) ec2() *EC2Details {
	if r.EC2 == nil {
		r.EC2 = &EC2Details{}
	}
	return r.EC2
}

func (r *resAcc) lambda() *LambdaDetails {
	if r.Lambda == nil {
		r.Lambda = &LambdaDetails{}
	}
	return r.Lambda
}

func (r *resAcc) mergeTags(tags map[string]string) {
	for k, v := range tags {
		if r.Tags == nil {
			r.Tags = map[string]string{}
		}
		if _, ok := r.Tags[k]; !ok && len(r.Tags) < maxTags {
			r.Tags[k] = v
		}
	}
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// queryFindings pages ListFindings for every covered resource, 10 IDs per
// call, on up to workers goroutines.
func (s *scan) queryFindings(ctx context.Context) error {
	s.mu.Lock()
	ids := append([]string(nil), s.order...)
	s.mu.Unlock()
	sort.Strings(ids)
	var batches [][]string
	for i := 0; i < len(ids); i += idsPerCall {
		batches = append(batches, ids[i:min(i+idsPerCall, len(ids))])
	}

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		firstEr error
		next    = make(chan []string)
	)
	for w := 0; w < min(workers, len(batches)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range next {
				if err := s.queryBatch(ctx, b); err != nil {
					errOnce.Do(func() { firstEr = err })
				}
			}
		}()
	}
	for _, b := range batches {
		if ctx.Err() != nil {
			break
		}
		next <- b
	}
	close(next)
	wg.Wait()
	if firstEr == nil && ctx.Err() != nil {
		s.mu.Lock()
		s.stop()
		s.mu.Unlock()
	}
	return firstEr
}

func (s *scan) filterCriteria(ids []string) *itypes.FilterCriteria {
	fc := &itypes.FilterCriteria{
		FindingStatus: []itypes.StringFilter{eq("ACTIVE")},
		ResourceType:  []itypes.StringFilter{eq(s.payload.ResourceType)},
		FindingType:   []itypes.StringFilter{eq("PACKAGE_VULNERABILITY"), eq("CODE_VULNERABILITY")},
	}
	for _, id := range ids {
		fc.ResourceId = append(fc.ResourceId, eq(id))
	}
	for _, sev := range s.payload.Severities {
		fc.Severity = append(fc.Severity, eq(sev))
	}
	if s.payload.FixAvailable != "" {
		fc.FixAvailable = []itypes.StringFilter{eq(s.payload.FixAvailable)}
	}
	if s.payload.ExploitAvailable != "" {
		fc.ExploitAvailable = []itypes.StringFilter{eq(s.payload.ExploitAvailable)}
	}
	return fc
}

func (s *scan) queryBatch(ctx context.Context, ids []string) error {
	var next *string
	for {
		if err := s.spend(ctx); err != nil {
			return err
		}
		out, err := s.insp.ListFindings(ctx, &inspector2.ListFindingsInput{
			FilterCriteria: s.filterCriteria(ids), MaxResults: aws.Int32(100), NextToken: next,
		})
		if err != nil {
			if s.budgetErr(ctx, err) {
				return err
			}
			return fmt.Errorf("inspector list findings: %w", err)
		}
		s.mu.Lock()
		for i := range out.Findings {
			s.addFinding(&out.Findings[i])
		}
		s.mu.Unlock()
		if aws.ToString(out.NextToken) == "" {
			return nil
		}
		next = out.NextToken
	}
}
