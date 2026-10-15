package running_image_vulnerabilities

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// hashesPerCall is Inspector's limit on values per ListFindings string
// filter (verified: 11 ecrImageHash values fail validation).
const hashesPerCall = 10

var severityRank = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "UNTRIAGED": 0}

// queryFindings reads Inspector coverage and findings for every platform
// image, in batches of hashesPerCall.
func (s *scan) queryFindings(ctx context.Context) error {
	s.groups = map[string]*groupAcc{}
	keys := make([]platformKey, 0, len(s.status))
	for pk := range s.status {
		keys = append(keys, pk)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].digest+keys[i].repo < keys[j].digest+keys[j].repo })
	var batches [][]platformKey
	for start := 0; start < len(keys); start += hashesPerCall {
		batches = append(batches, keys[start:min(start+hashesPerCall, len(keys))])
	}
	return forEach(len(batches), func(i int) error {
		batch := batches[i]
		status, err := s.coverage(ctx, batch)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		var hashes []string
		for _, pk := range batch {
			if !seen[pk.digest] {
				seen[pk.digest] = true
				hashes = append(hashes, pk.digest)
			}
		}
		if err := s.queryBatch(ctx, hashes); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, pk := range batch {
			s.status[pk] = status[pk]
			if !isGap(status[pk]) {
				for _, img := range s.platforms[pk] {
					img.assessed = true
				}
			}
		}
		return nil
	})
}

// coverage returns Inspector's scan status for one batch of platform images.
func (s *scan) coverage(ctx context.Context, batch []platformKey) (map[platformKey]string, error) {
	byARN := map[string]platformKey{}
	fc := &itypes.CoverageFilterCriteria{}
	status := map[platformKey]string{}
	for _, pk := range batch {
		arn := fmt.Sprintf("arn:aws:ecr:%s:%s:repository/%s/%s", s.region, pk.registry, pk.repo, pk.digest)
		byARN[arn] = pk
		status[pk] = statusNotCovered
		fc.ResourceId = append(fc.ResourceId, itypes.CoverageStringFilter{Comparison: itypes.CoverageStringComparisonEquals, Value: aws.String(arn)})
	}
	var next *string
	for {
		if err := s.spend(ctx); err != nil {
			return nil, err
		}
		s.countCall(&s.report.InspectorCalls)
		out, err := s.insp.ListCoverage(ctx, &inspector2.ListCoverageInput{FilterCriteria: fc, MaxResults: aws.Int32(200), NextToken: next})
		if err != nil {
			if s.budgetErr(ctx, err) {
				return nil, err
			}
			return nil, fmt.Errorf("inspector list coverage: %w", err)
		}
		for _, r := range out.CoveredResources {
			pk, ok := byARN[aws.ToString(r.ResourceId)]
			if !ok || r.ScanStatus == nil {
				continue
			}
			st := string(r.ScanStatus.StatusCode)
			if r.ScanStatus.Reason != "" && r.ScanStatus.Reason != itypes.ScanStatusReasonSuccessful {
				st += "/" + string(r.ScanStatus.Reason)
			}
			status[pk] = st
		}
		if aws.ToString(out.NextToken) == "" {
			return status, nil
		}
		next = out.NextToken
	}
}

func (s *scan) filterCriteria(hashes []string) *itypes.FilterCriteria {
	eq := func(v string) itypes.StringFilter {
		return itypes.StringFilter{Comparison: itypes.StringComparisonEquals, Value: aws.String(v)}
	}
	fc := &itypes.FilterCriteria{
		FindingStatus: []itypes.StringFilter{eq("ACTIVE")},
		ResourceType:  []itypes.StringFilter{eq("AWS_ECR_CONTAINER_IMAGE")},
	}
	for _, h := range hashes {
		fc.EcrImageHash = append(fc.EcrImageHash, eq(h))
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

func (s *scan) queryBatch(ctx context.Context, hashes []string) error {
	var next *string
	for {
		if err := s.spend(ctx); err != nil {
			return err
		}
		s.countCall(&s.report.InspectorCalls)
		out, err := s.insp.ListFindings(ctx, &inspector2.ListFindingsInput{
			FilterCriteria: s.filterCriteria(hashes), MaxResults: aws.Int32(100), NextToken: next,
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

// groupAcc accumulates one group.
type groupAcc struct {
	key, title, severity string
	findings             int
	sevCounts            map[string]int
	images               map[*runningImage]bool
	vulns                map[string]bool
	packages             map[PackageFix]bool
	fix, exploit         string
	epss                 float64
}

// addFinding must be called with mu held.
func (s *scan) addFinding(f *itypes.Finding) {
	var imgs []*runningImage
	for _, r := range f.Resources {
		if r.Details == nil || r.Details.AwsEcrContainerImage == nil {
			continue
		}
		d := r.Details.AwsEcrContainerImage
		pk := platformKey{aws.ToString(d.Registry), aws.ToString(d.RepositoryName), aws.ToString(d.ImageHash)}
		imgs = append(imgs, s.platforms[pk]...)
	}
	if len(imgs) == 0 {
		return // same hash in a repository nothing here runs from
	}
	sev := string(f.Severity)
	s.report.TotalFindings++
	s.report.SeverityCounts[sev]++

	vulnID, pkgs := "", []PackageFix(nil)
	if v := f.PackageVulnerabilityDetails; v != nil {
		vulnID = aws.ToString(v.VulnerabilityId)
		for _, p := range v.VulnerablePackages {
			pkgs = append(pkgs, PackageFix{Name: aws.ToString(p.Name), Version: aws.ToString(p.Version), FixedInVersion: aws.ToString(p.FixedInVersion)})
		}
	}
	if vulnID == "" {
		vulnID = aws.ToString(f.Title)
	}

	var keys []string
	switch s.payload.GroupBy {
	case GroupByPackage:
		for _, p := range pkgs {
			keys = append(keys, p.Name)
		}
		if len(keys) == 0 {
			keys = []string{"(no package)"}
		}
	case GroupByImage:
		for _, img := range imgs {
			keys = append(keys, img.repo+"@"+img.digest)
		}
	default:
		keys = []string{vulnID}
	}

	for _, key := range dedupe(keys) {
		g := s.groups[key]
		if g == nil {
			g = &groupAcc{key: key, sevCounts: map[string]int{}, images: map[*runningImage]bool{}, vulns: map[string]bool{}, packages: map[PackageFix]bool{}}
			s.groups[key] = g
		}
		g.findings++
		g.sevCounts[sev]++
		if severityRank[sev] > severityRank[g.severity] || g.severity == "" {
			g.severity = sev
		}
		g.vulns[vulnID] = true
		for _, p := range pkgs {
			if s.payload.GroupBy != GroupByPackage || p.Name == key {
				g.packages[p] = true
			}
		}
		for _, img := range imgs {
			if s.payload.GroupBy != GroupByImage || img.repo+"@"+img.digest == key {
				g.images[img] = true
			}
		}
		if s.payload.GroupBy == GroupByVulnerability {
			g.title = aws.ToString(f.Title)
			g.fix = string(f.FixAvailable)
			g.exploit = string(f.ExploitAvailable)
		}
		if s.payload.GroupBy == GroupByImage {
			for img := range g.images {
				g.title = img.display
			}
		}
		if f.Epss != nil && f.Epss.Score > g.epss {
			g.epss = f.Epss.Score
		}
	}
	for _, img := range imgs {
		img.matched = true
	}
}

func dedupe(v []string) []string {
	seen := map[string]bool{}
	out := v[:0:0]
	for _, x := range v {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// finish turns the accumulators into the sorted, capped report.
func (s *scan) finish() {
	s.report.Coverage.PlatformImages = len(s.status)
	for _, st := range s.status {
		s.report.Coverage.ScanStatus[st]++
	}
	for _, img := range s.images {
		if img.assessed {
			s.report.Coverage.AssessedImages++
		} else if img.platforms != nil {
			s.report.Coverage.UnscannedImages++
		}
		if img.matched {
			s.report.Coverage.ImagesWithFindings++
		}
	}
	groups := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		groups = append(groups, g.toGroup())
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if (a.ExploitAvailable == "YES") != (b.ExploitAvailable == "YES") {
			return a.ExploitAvailable == "YES"
		}
		if a.Images != b.Images {
			return a.Images > b.Images
		}
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		return a.Key < b.Key
	})
	s.report.GroupsTotal = len(groups)
	if len(groups) > s.payload.Limit {
		groups = groups[:s.payload.Limit]
	}
	s.report.Groups = groups
}

func (g *groupAcc) toGroup() Group {
	out := Group{
		Key: g.key, Title: g.title, Severity: g.severity, Findings: g.findings,
		SeverityCounts: g.sevCounts, Images: len(g.images), Vulnerabilities: len(g.vulns),
		FixAvailable: g.fix, ExploitAvailable: g.exploit, EPSS: g.epss,
	}
	vulns := make([]string, 0, len(g.vulns))
	for v := range g.vulns {
		vulns = append(vulns, v)
	}
	sort.Strings(vulns)
	if len(vulns) > 1 || g.key != firstOr(vulns) {
		out.VulnerabilityIDs = capList(vulns)
	}
	pkgs := make([]PackageFix, 0, len(g.packages))
	for p := range g.packages {
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name+"\x00"+pkgs[i].Version < pkgs[j].Name+"\x00"+pkgs[j].Version
	})
	if len(pkgs) > maxListed {
		pkgs = pkgs[:maxListed]
	}
	out.Packages = pkgs
	wl := map[string]bool{}
	for img := range g.images {
		for w := range img.workloads {
			wl[w] = true
		}
	}
	workloads := make([]string, 0, len(wl))
	for w := range wl {
		workloads = append(workloads, w)
	}
	sort.Strings(workloads)
	out.WorkloadsTotal = len(workloads)
	out.Workloads = capList(workloads)
	return out
}

func capList(v []string) []string {
	if len(v) > maxListed {
		return v[:maxListed]
	}
	return v
}

func firstOr(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return strings.TrimSpace(v[0])
}
