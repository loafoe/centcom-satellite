package running_image_vulnerabilities

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

func TestMaxCvssBaseScore(t *testing.T) {
	cases := []struct {
		name string
		f    *itypes.Finding
		want float64
	}{
		{"no package vulnerability details", &itypes.Finding{}, 0},
		{"no cvss entries", &itypes.Finding{PackageVulnerabilityDetails: &itypes.PackageVulnerabilityDetails{}}, 0},
		{
			"single source",
			&itypes.Finding{PackageVulnerabilityDetails: &itypes.PackageVulnerabilityDetails{
				Cvss: []itypes.CvssScore{{BaseScore: aws.Float64(7.5), Source: aws.String("NVD")}},
			}},
			7.5,
		},
		{
			"picks the highest across disagreeing sources",
			&itypes.Finding{PackageVulnerabilityDetails: &itypes.PackageVulnerabilityDetails{
				Cvss: []itypes.CvssScore{
					{BaseScore: aws.Float64(5.3), Source: aws.String("NVD")},
					{BaseScore: aws.Float64(9.8), Source: aws.String("RedHat")},
				},
			}},
			9.8,
		},
		{
			"nil base score entry is skipped, not treated as zero-wins",
			&itypes.Finding{PackageVulnerabilityDetails: &itypes.PackageVulnerabilityDetails{
				Cvss: []itypes.CvssScore{{Source: aws.String("NVD")}, {BaseScore: aws.Float64(4.1), Source: aws.String("RedHat")}},
			}},
			4.1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := maxCvssBaseScore(c.f); got != c.want {
				t.Errorf("maxCvssBaseScore() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestAddFinding_GroupCarriesHighestCvssAndEpss proves the per-group
// accumulation (not just the pure extractor above) picks the maximum CVSS
// and EPSS across multiple findings merged into the same vulnerability
// group — the shape the new top-50-by-CVSS/EPSS CVE table depends on.
func TestAddFinding_GroupCarriesHighestCvssAndEpss(t *testing.T) {
	s := &scan{payload: Payload{GroupBy: GroupByVulnerability}, groups: map[string]*groupAcc{}, report: Report{SeverityCounts: map[string]int{}}}
	img := &runningImage{repo: "app/web", digest: amdDigest, workloads: map[string]bool{}}
	s.platforms = map[platformKey][]*runningImage{{registry: testAccount, repo: "app/web", digest: amdDigest}: {img}}

	f1 := finding("app/web", amdDigest, "CVE-9", "CRITICAL", "tomcat", "9.0.62", "11.0.2")
	f1.PackageVulnerabilityDetails.Cvss = []itypes.CvssScore{{BaseScore: aws.Float64(6.1), Source: aws.String("NVD")}}
	f1.Epss = &itypes.EpssDetails{Score: 0.2}

	f2 := finding("app/web", amdDigest, "CVE-9", "CRITICAL", "tomcat", "9.0.62", "11.0.2")
	f2.PackageVulnerabilityDetails.Cvss = []itypes.CvssScore{{BaseScore: aws.Float64(9.8), Source: aws.String("RedHat")}}
	f2.Epss = &itypes.EpssDetails{Score: 0.87}

	s.addFinding(&f1)
	s.addFinding(&f2)

	g := s.groups["CVE-9"].toGroup()
	if g.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8 (the higher of the two findings)", g.CVSS)
	}
	if g.EPSS != 0.87 {
		t.Errorf("EPSS = %v, want 0.87 (the higher of the two findings)", g.EPSS)
	}
}
