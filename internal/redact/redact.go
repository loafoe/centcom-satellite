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

// minEntropyLen is the minimum token length before the high-entropy heuristic
// applies. Short config values (ports, enums, booleans) are never
// entropy-redacted. Must exceed 2^entropyThreshold (~21.1 at 4.4): a string
// of N all-distinct characters tops out at exactly log2(N) bits/char, so at
// or below that length the check could never fire regardless of content.
const minEntropyLen = 24

// entropyThreshold is the Shannon entropy (bits/char) above which a token is
// treated as a likely secret (raw token, base64 blob, random key).
//
// Calibrated empirically (2026-09-05, against a real Grafana Alloy ConfigMap
// that was being fully redacted): structured-but-benign technical tokens -
// URLs, OTTL processor expressions, Prometheus label selectors, dotted
// attribute paths - commonly land at 4.0-4.3 bits/char purely from mixed
// case/punctuation, with the worst observed real sample (a full HTTPS URL) at
// 4.27. Genuine secret-shaped tokens (AWS secret keys, Grafana/API service
// tokens, JWTs, and this package's own random-token test fixture) all score
// 4.5+. 4.4 sits in the gap between those two clusters.
//
// Known v1 limitation: a short, low-entropy credential (e.g. a ~20-char AWS access
// key id at ~3.7 bits/char) stored under a benign-looking key name — i.e. one that
// does not match secretKeyNameRe — can slip through this net and be returned in
// cleartext. The key-name, PEM, and inline-secret heuristics catch the common cases;
// tightening the entropy band (and adding name allow/deny lists) is deferred to v2.
const entropyThreshold = 4.4

var (
	// secretKeyNameRe matches key names that conventionally hold secrets.
	secretKeyNameRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)`)

	// inlineSecretRe matches embedded "password=...", "token: ...", etc. inside a value
	// (e.g. connection strings, .env dumps). Captures the token right after the
	// separator so isLiteralValue can tell an actual literal from a config-language
	// reference/flag (see below) — this must stay a capturing group, not \S.
	inlineSecretRe = regexp.MustCompile(`(?i)(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*(\S+)`)

	// dottedIdentifierRe matches bare, unquoted attribute-reference chains like
	// `local.file.spiffe_jwt.content` or `otelcol.auth.bearer.spiffe.handler` -
	// how HCL-family config languages (Grafana Alloy/Flow, Terraform) point at
	// another block's exported value rather than inlining one. The referenced
	// value lives elsewhere (often a mounted secret file, never in this text),
	// so this is structural syntax, not a literal secret.
	dottedIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)
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
	if hasInlineSecret(value) {
		return ReasonInlineSecret
	}
	if hasHighEntropyToken(value) {
		return ReasonHighEntropy
	}
	return ""
}

// hasHighEntropyToken reports whether value contains a contiguous
// whitespace-delimited token (its own base unit — a real secret is one
// unbroken blob, not spread across a document) that is itself long and
// random-looking. Scored per-token rather than over the whole value: a large
// multi-line config document built from many short, ordinary words/tokens
// can rack up several distinct characters in aggregate (which reads as
// deceptively "high entropy" if scored as one blob) without any single token
// in it actually being secret-shaped.
func hasHighEntropyToken(value string) bool {
	for _, tok := range strings.Fields(value) {
		if len(tok) >= minEntropyLen && ShannonEntropy(tok) > entropyThreshold {
			return true
		}
	}
	return false
}

// hasInlineSecret reports whether value contains at least one occurrence of
// "password=...", "token: ...", etc. where the right-hand side is an actual
// literal (quoted string, raw token/blob) rather than a boolean flag
// (`is_secret = true`) or a bare config-language attribute reference
// (`token = local.file.spiffe_jwt.content`). Checks every match rather than
// stopping at the first, since one value can legitimately contain several
// "key = ref" pairs alongside zero or more real literals.
func hasInlineSecret(value string) bool {
	for _, m := range inlineSecretRe.FindAllStringSubmatch(value, -1) {
		if isLiteralValue(m[1]) {
			return true
		}
	}
	return false
}

// isLiteralValue reports whether tok (the raw text immediately following a
// "key =" / "key:" separator) looks like an actual literal value worth
// redacting, as opposed to config-language syntax: a boolean keyword
// (`true`/`false`) or a bare dotted identifier chain both return false.
func isLiteralValue(tok string) bool {
	switch strings.ToLower(tok) {
	case "true", "false":
		return false
	}
	return !dottedIdentifierRe.MatchString(tok)
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
