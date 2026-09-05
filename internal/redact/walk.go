package redact

import "fmt"

// Placeholder replaces a redacted string leaf. Named per-reason (rather than
// a bare "[REDACTED]") so a caller can see *why* without re-running the
// heuristic, and includes the original length so an all-zero-length report
// doesn't look identical to a masked one.
func placeholder(reason Reason, originalLen int) string {
	return fmt.Sprintf("[REDACTED: %s, %d chars]", reason, originalLen)
}

// WalkObject recursively walks an arbitrary JSON-like value — the shape
// produced by unstructured.Unstructured.Object: nested map[string]any,
// []any, and scalar leaves — and returns a deep copy with every string leaf
// that Check flags replaced by a placeholder. The immediate parent map key is
// used as the key-name context for Check (matching get_configmap's
// key/value redaction); list elements inherit the enclosing field's key.
//
// Returns the redacted copy and the number of leaves redacted, so a caller
// can report "N values redacted" without walking the result a second time.
func WalkObject(v any) (any, int) {
	return walk("", v)
}

func walk(keyHint string, v any) (any, int) {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		count := 0
		// Special-case Kubernetes' extremely common {name: "X", value: "Y"}
		// pair shape (Pod env vars, EnvFrom-style sources, many CRD fields).
		// The semantically meaningful key for redaction purposes is the
		// STRING VALUE of "name" (e.g. "DB_PASSWORD"), not the literal JSON
		// key "value" - checking against the literal key would only ever
		// see the word "value" itself and never fire the secret-key-name
		// heuristic, missing exactly the case (a password in a Pod's env)
		// this layer exists to catch.
		envNameHint, isNameValuePair := val["name"].(string)
		for k, vv := range val {
			hint := k
			if isNameValuePair && k == "value" {
				hint = envNameHint
			}
			redacted, c := walk(hint, vv)
			out[k] = redacted
			count += c
		}
		return out, count
	case []any:
		out := make([]any, len(val))
		count := 0
		for i, vv := range val {
			redacted, c := walk(keyHint, vv)
			out[i] = redacted
			count += c
		}
		return out, count
	case string:
		if reason := Check(keyHint, val); reason != "" {
			return placeholder(reason, len(val)), 1
		}
		return val, 0
	default:
		// Numbers, bools, nil: never redacted — the heuristics only ever
		// look at string content.
		return val, 0
	}
}
