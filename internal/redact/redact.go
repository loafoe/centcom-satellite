// Package redact provides a shared heuristic for masking secret-shaped
// values in otherwise-legitimate Kubernetes objects. Originally specific to
// get_configmap, generalized so get_resource (and any future generic
// resource reader) can apply the same protection to arbitrary object graphs.
package redact

import (
	"math"
	"regexp"
	"strings"
)

// Reason describes why a value was masked. Empty string means not redacted.
type Reason string

const (
	ReasonSecretKeyName Reason = "secret-key-name"
	ReasonPEMBlock      Reason = "pem-block"
	ReasonInlineSecret  Reason = "inline-secret"
	ReasonHighEntropy   Reason = "high-entropy"
)

// minEntropyLen is the minimum value length before the high-entropy heuristic applies.
// Short config values (ports, enums, booleans) are never entropy-redacted.
const minEntropyLen = 20

// entropyThreshold is the Shannon entropy (bits/char) above which a long string is
// treated as a likely secret (raw token, base64 blob, random key).
//
// Known v1 limitation: a short, low-entropy credential (e.g. a ~20-char AWS access
// key id at ~3.7 bits/char) stored under a benign-looking key name — i.e. one that
// does not match secretKeyNameRe — can slip through this net and be returned in
// cleartext. The key-name, PEM, and inline-secret heuristics catch the common cases;
// tightening the entropy band (and adding name allow/deny lists) is deferred to v2.
const entropyThreshold = 4.0

var (
	// secretKeyNameRe matches key names that conventionally hold secrets.
	secretKeyNameRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)`)

	// inlineSecretRe matches embedded "password=...", "token: ...", etc. inside a value
	// (e.g. connection strings, .env dumps). Requires at least one non-space char after.
	inlineSecretRe = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S`)
)

// Check decides whether a value should be masked given its key name context,
// returning the reason (empty if the value is safe to return as-is). The
// decision uses, in order: secret-like key name, PEM block, inline secret
// pattern, then high Shannon entropy.
func Check(key, value string) Reason {
	if secretKeyNameRe.MatchString(key) {
		return ReasonSecretKeyName
	}
	if strings.Contains(value, "-----BEGIN") {
		return ReasonPEMBlock
	}
	if inlineSecretRe.MatchString(value) {
		return ReasonInlineSecret
	}
	if len(value) >= minEntropyLen && ShannonEntropy(value) > entropyThreshold {
		return ReasonHighEntropy
	}
	return ""
}

// ShannonEntropy returns the Shannon entropy of s in bits per character.
func ShannonEntropy(s string) float64 {
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
