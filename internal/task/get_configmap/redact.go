package get_configmap

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// redactionReason describes why a value was masked. Empty string means not redacted.
type redactionReason string

const (
	reasonSecretKeyName redactionReason = "secret-key-name"
	reasonPEMBlock      redactionReason = "pem-block"
	reasonInlineSecret  redactionReason = "inline-secret"
	reasonHighEntropy   redactionReason = "high-entropy"
)

// minEntropyLen is the minimum value length before the high-entropy heuristic applies.
// Short config values (ports, enums, booleans) are never entropy-redacted.
const minEntropyLen = 20

// entropyThreshold is the Shannon entropy (bits/char) above which a long string is
// treated as a likely secret (raw token, base64 blob, random key).
const entropyThreshold = 4.0

var (
	// secretKeyNameRe matches key names that conventionally hold secrets.
	secretKeyNameRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)`)

	// inlineSecretRe matches embedded "password=...", "token: ...", etc. inside a value
	// (e.g. connection strings, .env dumps). Requires at least one non-space char after.
	inlineSecretRe = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S`)
)

// redact decides whether a ConfigMap value should be masked, returning the reason
// (empty if the value is safe to return as-is). The decision uses, in order:
// secret-like key name, PEM block, inline secret pattern, then high Shannon entropy.
func redact(key, value string) redactionReason {
	if secretKeyNameRe.MatchString(key) {
		return reasonSecretKeyName
	}
	if strings.Contains(value, "-----BEGIN") {
		return reasonPEMBlock
	}
	if inlineSecretRe.MatchString(value) {
		return reasonInlineSecret
	}
	if len(value) >= minEntropyLen && shannonEntropy(value) > entropyThreshold {
		return reasonHighEntropy
	}
	return ""
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	total := float64(len([]rune(s)))
	var entropy float64
	for _, c := range counts {
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
