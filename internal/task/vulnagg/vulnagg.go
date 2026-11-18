// Package vulnagg merges Inspector's per-finding fixAvailable /
// exploitAvailable values when several findings (resources, images) roll up
// into one vulnerability row. The merge must not depend on the order
// findings arrive in (scans page Inspector concurrently): the most
// actionable value wins, YES > PARTIAL > NO for a fix and YES > NO for an
// exploit, i.e. "a fix exists for at least one affected resource".
package vulnagg

var fixRank = map[string]int{"YES": 3, "PARTIAL": 2, "NO": 1}

// MergeFix returns the more actionable of two fixAvailable values.
func MergeFix(cur, next string) string {
	if fixRank[next] > fixRank[cur] {
		return next
	}
	return cur
}

var exploitRank = map[string]int{"YES": 2, "NO": 1}

// MergeExploit returns the more severe of two exploitAvailable values.
func MergeExploit(cur, next string) string {
	if exploitRank[next] > exploitRank[cur] {
		return next
	}
	return cur
}
