package vulnagg

import (
	"fmt"
	"strings"
)

// MaxVulnerabilityIDs is Inspector's limit on values per FilterCriteria
// field: one vulnerability_ids filter is one ListFindings call.
const MaxVulnerabilityIDs = 10

// CleanIDs trims, drops empty entries and dedupes a filter list (order
// kept). upper uppercases (CVE/GHSA IDs); more than max entries is an error.
func CleanIDs(field string, ids []string, max int, upper bool) ([]string, string) {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if upper {
			id = strings.ToUpper(id)
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) > max {
		return nil, fmt.Sprintf("%s takes at most %d entries (got %d)", field, max, len(out))
	}
	return out, ""
}
