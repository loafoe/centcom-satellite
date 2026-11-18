// Package vulnrecency holds the "prefer recently observed" truncation shared
// by the Inspector vulnerability tasks. A brand-new CVE typically has no
// EPSS score yet, often no known exploit and only a few affected resources,
// so every task's normal ordering (severity, exploit, spread) sorts it near
// the bottom — exactly where a result limit cuts. Keeping recently observed
// rows ahead of the cut makes sure a caller that re-sorts or flags new CVEs
// (centcom's Vulnerability Intelligence) actually receives them.
package vulnrecency

import "time"

// MaxDays caps prefer_recent_days.
const MaxDays = 90

// Clamp normalizes a prefer_recent_days payload value: <= 0 disables the
// preference, larger values are capped at MaxDays.
func Clamp(days int) int {
	if days <= 0 {
		return 0
	}
	return min(days, MaxDays)
}

// Keep returns at most limit items from sorted (already in the caller's
// display order). With days > 0, items first observed within the last days
// (per firstObserved; a zero time never counts as recent) are kept before
// any older item, so the limit only ever cuts older rows first; the result
// stays in the original order. With days <= 0 it is a plain prefix cut.
func Keep[T any](sorted []T, limit int, days int, now time.Time, firstObserved func(T) time.Time) []T {
	if len(sorted) <= limit {
		return sorted
	}
	if days <= 0 {
		return sorted[:limit]
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	keep := make([]bool, len(sorted))
	kept := 0
	for i, it := range sorted {
		if kept == limit {
			break
		}
		if t := firstObserved(it); !t.IsZero() && !t.Before(cutoff) {
			keep[i] = true
			kept++
		}
	}
	for i := range sorted {
		if kept == limit {
			break
		}
		if !keep[i] {
			keep[i] = true
			kept++
		}
	}
	out := make([]T, 0, limit)
	for i, it := range sorted {
		if keep[i] {
			out = append(out, it)
		}
	}
	return out
}
