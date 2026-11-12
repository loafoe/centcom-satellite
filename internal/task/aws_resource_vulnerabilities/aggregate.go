package aws_resource_vulnerabilities

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// addFinding folds one finding into both groupings; mu held.
func (s *scan) addFinding(f *itypes.Finding) {
	sev := string(f.Severity)
	vulnID, pkgs := "", []Package(nil)
	var cvss float64
	if v := f.PackageVulnerabilityDetails; v != nil {
		vulnID = aws.ToString(v.VulnerabilityId)
		for _, p := range v.VulnerablePackages {
			pkgs = append(pkgs, Package{
				Name: aws.ToString(p.Name), Version: versionOf(p), FixedInVersion: aws.ToString(p.FixedInVersion),
				PackageManager: string(p.PackageManager), FilePath: aws.ToString(p.FilePath),
				SourceLayer: aws.ToString(p.SourceLambdaLayerArn),
			})
		}
		for _, c := range v.Cvss {
			if c.BaseScore != nil && *c.BaseScore > cvss {
				cvss = *c.BaseScore
			}
		}
	}
	if vulnID == "" {
		vulnID = aws.ToString(f.Title)
	}
	if vulnID == "" {
		return
	}

	var resIDs []string
	for _, r := range f.Resources {
		id := aws.ToString(r.Id)
		if id == "" {
			continue
		}
		resIDs = append(resIDs, id)
		s.mergeResourceDetails(s.resource(id), &r)
	}
	if len(resIDs) == 0 {
		return
	}

	s.report.TotalFindings++
	s.report.SeverityCounts[sev]++

	v := s.vulns[vulnID]
	if v == nil {
		v = &vulnAcc{
			Vulnerability: Vulnerability{ID: vulnID, Type: string(f.Type)},
			resources:     map[string]bool{}, packages: map[Package]bool{},
		}
		s.vulns[vulnID] = v
	}
	v.Findings++
	if v.Severity == "" || severityRank[sev] > severityRank[v.Severity] {
		v.Severity = sev
	}
	if v.Title == "" {
		v.Title = aws.ToString(f.Title)
	}
	if v.Description == "" {
		v.Description = truncate(aws.ToString(f.Description), maxDescription)
	}
	if f.Remediation != nil && f.Remediation.Recommendation != nil && v.Remediation == "" {
		if t := aws.ToString(f.Remediation.Recommendation.Text); t != "" && t != "None Provided" {
			v.Remediation = truncate(t, maxDescription)
		}
	}
	if d := f.PackageVulnerabilityDetails; d != nil && v.SourceURL == "" {
		v.SourceURL = aws.ToString(d.SourceUrl)
		v.ReferenceURLs = capN(d.ReferenceUrls, maxReferences)
		v.VendorSeverity = aws.ToString(d.VendorSeverity)
	}
	if c := f.CodeVulnerabilityDetails; c != nil {
		if len(v.CWEs) == 0 {
			v.CWEs = c.Cwes
		}
		v.Detector = first(v.Detector, aws.ToString(c.DetectorName))
		if len(v.ReferenceURLs) == 0 {
			v.ReferenceURLs = capN(c.ReferenceUrls, maxReferences)
		}
		if fp := c.FilePath; fp != nil {
			pkgs = append(pkgs, Package{Name: aws.ToString(fp.FileName), FilePath: aws.ToString(fp.FilePath), SourceLayer: aws.ToString(c.SourceLambdaLayerArn)})
		}
	}
	v.CVSS = max(v.CVSS, cvss)
	if f.Epss != nil {
		v.EPSS = max(v.EPSS, f.Epss.Score)
	}
	v.InspectorScore = max(v.InspectorScore, aws.ToFloat64(f.InspectorScore))
	if fa := string(f.FixAvailable); fa != "" && (v.FixAvailable == "" || fa == "YES") {
		v.FixAvailable = fa
	}
	if ea := string(f.ExploitAvailable); ea == "YES" || v.ExploitAvailable == "" {
		if ea != "" {
			v.ExploitAvailable = ea
		}
	}
	if e := f.ExploitabilityDetails; e != nil && e.LastKnownExploitAt != nil {
		v.LastKnownExploitAt = e.LastKnownExploitAt.UTC().Format(time.RFC3339)
	}
	if t := f.FirstObservedAt; t != nil && (v.first.IsZero() || t.Before(v.first)) {
		v.first = *t
	}
	if t := f.LastObservedAt; t != nil && t.After(v.last) {
		v.last = *t
	}
	for _, p := range pkgs {
		v.packages[p] = true
	}

	for _, id := range resIDs {
		v.resources[id] = true
		r := s.resources[id]
		r.Findings++
		r.SeverityCounts[sev]++
		r.vulns[vulnID] = true
		if len(pkgs) > 0 && r.pkgs[vulnID] == nil {
			r.pkgs[vulnID] = map[Package]bool{}
		}
		for _, p := range pkgs {
			r.pkgs[vulnID][p] = true
		}
		if v.FixAvailable == "YES" || string(f.FixAvailable) == "YES" {
			r.fixable[vulnID] = true
		}
		if string(f.ExploitAvailable) == "YES" {
			r.exploitable[vulnID] = true
		}
		r.MaxCVSS = max(r.MaxCVSS, cvss)
		if f.Epss != nil {
			r.MaxEPSS = max(r.MaxEPSS, f.Epss.Score)
		}
	}
}

func versionOf(p itypes.VulnerablePackage) string {
	v := aws.ToString(p.Version)
	if r := aws.ToString(p.Release); r != "" {
		v += "-" + r
	}
	return v
}

// mergeResourceDetails fills resource fields from a finding's resource; mu held.
func (s *scan) mergeResourceDetails(r *resAcc, fr *itypes.Resource) {
	r.mergeTags(fr.Tags)
	if fr.Details == nil {
		return
	}
	if e := fr.Details.AwsEc2Instance; e != nil {
		d := r.ec2()
		d.InstanceType = first(d.InstanceType, aws.ToString(e.Type))
		d.Platform = first(d.Platform, aws.ToString(e.Platform))
		d.ImageID = first(d.ImageID, aws.ToString(e.ImageId))
		d.KeyName = first(d.KeyName, aws.ToString(e.KeyName))
		d.VpcID = first(d.VpcID, aws.ToString(e.VpcId))
		d.SubnetID = first(d.SubnetID, aws.ToString(e.SubnetId))
		d.IamInstanceProfile = first(d.IamInstanceProfile, aws.ToString(e.IamInstanceProfileArn))
		if e.LaunchedAt != nil && d.LaunchedAt == "" {
			d.LaunchedAt = e.LaunchedAt.UTC().Format(time.RFC3339)
		}
		if len(d.IPv4Addresses) == 0 {
			d.IPv4Addresses = e.IpV4Addresses
		}
	}
	if l := fr.Details.AwsLambdaFunction; l != nil {
		d := r.lambda()
		d.FunctionName = first(d.FunctionName, aws.ToString(l.FunctionName))
		d.Runtime = first(d.Runtime, string(l.Runtime))
		d.Version = first(d.Version, aws.ToString(l.Version))
		d.PackageType = first(d.PackageType, string(l.PackageType))
		d.ExecutionRole = first(d.ExecutionRole, aws.ToString(l.ExecutionRoleArn))
		if l.LastModifiedAt != nil && d.LastModifiedAt == "" {
			d.LastModifiedAt = l.LastModifiedAt.UTC().Format(time.RFC3339)
		}
		if len(d.Architectures) == 0 {
			for _, a := range l.Architectures {
				d.Architectures = append(d.Architectures, string(a))
			}
		}
		if len(d.Layers) == 0 {
			d.Layers = l.Layers
		}
	}
}

// finish builds the sorted, capped report; called once, after the scan.
func (s *scan) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cov := &s.report.Coverage
	vulns := make([]Vulnerability, 0, len(s.vulns))
	for _, v := range s.vulns {
		out := v.Vulnerability
		out.Resources = len(v.resources)
		out.ResourceIDs = capN(sortedKeys(v.resources), s.payload.ListLimit)
		out.Packages = sortedPackages(v.packages, s.payload.ListLimit)
		if !v.first.IsZero() {
			out.FirstObservedAt = v.first.UTC().Format(time.RFC3339)
		}
		if !v.last.IsZero() {
			out.LastObservedAt = v.last.UTC().Format(time.RFC3339)
		}
		vulns = append(vulns, out)
	}
	sort.Slice(vulns, func(i, j int) bool {
		a, b := vulns[i], vulns[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.Resources != b.Resources {
			return a.Resources > b.Resources
		}
		return a.ID < b.ID
	})
	byID := map[string]Vulnerability{}
	for _, v := range vulns {
		byID[v.ID] = v
	}
	s.report.VulnerabilitiesTotal = len(vulns)
	s.report.Vulnerabilities = capVulns(vulns, s.payload.Limit)

	cov.Resources, cov.Scanned, cov.NotScanned, cov.WithFindings = 0, 0, 0, 0
	cov.ScanStatus = map[string]int{}
	var res []Resource
	for _, id := range s.order {
		r := s.resources[id]
		if r.covered {
			cov.Resources++
			cov.ScanStatus[r.ScanStatus]++
			if r.ScanStatus == "ACTIVE" {
				cov.Scanned++
			} else {
				cov.NotScanned++
			}
		}
		if r.Findings == 0 {
			continue
		}
		cov.WithFindings++
		out := r.Resource
		out.Name = resourceName(r)
		out.Vulnerabilities = len(r.vulns)
		out.Fixable = len(r.fixable)
		out.Exploitable = len(r.exploitable)
		ids := sortedKeys(r.vulns)
		sort.SliceStable(ids, func(i, j int) bool {
			a, b := byID[ids[i]], byID[ids[j]]
			if severityRank[a.Severity] != severityRank[b.Severity] {
				return severityRank[a.Severity] > severityRank[b.Severity]
			}
			return a.CVSS > b.CVSS
		})
		out.VulnerabilityIDs = capN(ids, s.payload.ListLimit)
		for _, id := range out.VulnerabilityIDs {
			if len(r.pkgs[id]) == 0 {
				continue
			}
			if out.VulnerabilityPackages == nil {
				out.VulnerabilityPackages = map[string][]Package{}
			}
			out.VulnerabilityPackages[id] = sortedPackages(r.pkgs[id], s.payload.ListLimit)
		}
		res = append(res, out)
	}
	sort.Slice(res, func(i, j int) bool {
		a, b := res[i], res[j]
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED"} {
			if a.SeverityCounts[sev] != b.SeverityCounts[sev] {
				return a.SeverityCounts[sev] > b.SeverityCounts[sev]
			}
		}
		if a.MaxCVSS != b.MaxCVSS {
			return a.MaxCVSS > b.MaxCVSS
		}
		return a.ID < b.ID
	})
	s.report.ResourcesTotal = len(res)
	if len(res) > s.payload.Limit {
		res = res[:s.payload.Limit]
	}
	if res == nil {
		res = []Resource{}
	}
	s.report.Resources = res
}

func sortedPackages(set map[Package]bool, limit int) []Package {
	pkgs := make([]Package, 0, len(set))
	for p := range set {
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		return a.Name+"\x00"+a.Version+"\x00"+a.FilePath < b.Name+"\x00"+b.Version+"\x00"+b.FilePath
	})
	if len(pkgs) > limit {
		pkgs = pkgs[:limit]
	}
	return pkgs
}

func resourceName(r *resAcc) string {
	if r.Lambda != nil && r.Lambda.FunctionName != "" {
		return r.Lambda.FunctionName
	}
	if n := r.Tags["Name"]; n != "" {
		return n
	}
	return ""
}

func capVulns(v []Vulnerability, n int) []Vulnerability {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capN(v []string, n int) []string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + "…"
}
