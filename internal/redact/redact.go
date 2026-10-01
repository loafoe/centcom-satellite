// Package redact provides a shared heuristic for masking secret-shaped
// values in otherwise-legitimate Kubernetes objects. Originally specific to
// get_configmap, generalized so get_resource (and any future generic
// resource reader) can apply the same protection to arbitrary object graphs.
//
// Deliberately NOT included: a Shannon-entropy-based "this token looks
// random" heuristic (removed 2026-10, see git history for the prior
// implementation). It caused active harm in production: it masked
// legitimate, non-secret content (long technical tokens - URLs, OTTL
// expressions, label selectors - inside a HelmApplication's valuesObject)
// with a placeholder that read identically to the field simply being
// absent. A caller diffing a before/after for dropped fields had no way to
// tell "redacted" apart from "never there" in that document, and a prior
// incident showed exactly that confusion masking real data loss. The
// heuristics below are deliberately exact pattern matches - key name, PEM
// block, inline "key=value" - with no judgment call on what "looks random".
package redact

import (
	"regexp"
	"strings"
)

// Reason describes why a value was masked. Empty string means not redacted.
type Reason string

const (
	ReasonSecretKeyName Reason = "secret-key-name"
	ReasonPEMBlock      Reason = "pem-block"
	ReasonInlineSecret  Reason = "inline-secret"
)

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
// decision uses, in order: secret-like key name, PEM block, then inline
// secret pattern.
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
	return ""
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
