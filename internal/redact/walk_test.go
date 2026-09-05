package redact

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkObject_RedactsNestedStringLeaves(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"replicas": float64(3), // non-string leaves pass through untouched
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "hunter2",
				},
				map[string]any{
					"name":  "LOG_LEVEL",
					"value": "info",
				},
			},
		},
		"status": map[string]any{
			"message": "connection string: postgres://u:p@h/d?password=s3cr3t",
		},
	}

	redacted, count := WalkObject(obj)
	require.Equal(t, 2, count, "expected exactly the password value and the inline-secret message to be redacted")

	m := redacted.(map[string]any)
	spec := m["spec"].(map[string]any)
	assert.Equal(t, float64(3), spec["replicas"], "non-string leaves must pass through unchanged")

	env := spec["env"].([]any)
	firstEnv := env[0].(map[string]any)
	assert.True(t, strings.HasPrefix(firstEnv["value"].(string), "[REDACTED:"), "DB_PASSWORD value should be redacted")
	assert.Equal(t, "DB_PASSWORD", firstEnv["name"], "the key name itself is never redacted, only values")

	secondEnv := env[1].(map[string]any)
	assert.Equal(t, "info", secondEnv["value"], "a benign value must pass through unchanged")

	status := m["status"].(map[string]any)
	assert.True(t, strings.HasPrefix(status["message"].(string), "[REDACTED:"), "inline secret inside a message field should be redacted")
}

func TestWalkObject_EmptyAndScalarInputs(t *testing.T) {
	redacted, count := WalkObject(map[string]any{})
	assert.Equal(t, 0, count)
	assert.Equal(t, map[string]any{}, redacted)

	redacted, count = WalkObject("plain string")
	assert.Equal(t, 0, count)
	assert.Equal(t, "plain string", redacted)

	redacted, count = WalkObject(nil)
	assert.Equal(t, 0, count)
	assert.Nil(t, redacted)
}

func TestWalkObject_TopLevelSecretValueRedacted(t *testing.T) {
	redacted, count := WalkObject("api_key")
	// A bare string with no key context: Check("", "api_key") - the value
	// itself doesn't match the key-name pattern (that only matches the KEY,
	// not the value), isn't a PEM block, isn't an inline pattern, and is too
	// short for entropy. So a top-level scalar with no enclosing key is
	// realistically never redacted by this heuristic - documented via this
	// test so a future change to Check's signature doesn't silently change
	// that without a test noticing.
	assert.Equal(t, 0, count)
	assert.Equal(t, "api_key", redacted)
}
