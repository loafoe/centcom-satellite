package get_configmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact_Matrix(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		value  string
		reason redactionReason
	}{
		// Safe config values pass through — this is the Cilium-WireGuard case.
		{"boolean flag", "enable-wireguard", "true", ""},
		{"cluster name", "cluster-name", "prod-eu", ""},
		{"port number", "listen-port", "8080", ""},
		{"short enum", "log-level", "info", ""},
		{"plain hostname", "endpoint", "loki.monitoring.svc", ""},

		// Secret-like key names redact regardless of value.
		{"password key", "db-password", "hunter2", reasonSecretKeyName},
		{"token key", "bearer-token", "x", reasonSecretKeyName},
		{"apikey underscore", "api_key", "abc", reasonSecretKeyName},
		{"private key name", "tls-private-key", "...", reasonSecretKeyName},
		{"credential key", "aws-credentials", "...", reasonSecretKeyName},

		// PEM blocks redact.
		{"pem block", "ca", "-----BEGIN CERTIFICATE-----\nMIIB...", reasonPEMBlock},

		// Inline secrets inside otherwise-innocent keys.
		{"connection string", "db-url", "postgres://u:p@h/d?password=s3cr3t", reasonInlineSecret},
		{"env dump", "config", "DEBUG=true\nAPI_TOKEN=abcdef", reasonInlineSecret},

		// High-entropy long strings redact; long-but-structured stays.
		{"random token", "data", "aB3xY9zQw7Lp2Km5Nv8Rt4Hs6Jd0Fg1", reasonHighEntropy},
		{"long english prose", "notes", "this is a perfectly ordinary sentence of config documentation", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reason, redact(tt.key, tt.value),
				"key=%q value=%q", tt.key, tt.value)
		})
	}
}

func TestRedact_EntropyLengthBoundary(t *testing.T) {
	// A high-entropy string of exactly minEntropyLen (20) chars is evaluated;
	// one char shorter is exempt from the entropy heuristic.
	high20 := "aB3xY9zQw7Lp2Km5Nv8R" // 20 chars, high entropy
	assert.Equal(t, reasonHighEntropy, redact("data", high20))
	assert.Len(t, high20, minEntropyLen)

	high19 := "aB3xY9zQw7Lp2Km5Nv8" // 19 chars
	assert.Equal(t, redactionReason(""), redact("data", high19),
		"values shorter than minEntropyLen are exempt from the entropy heuristic")
}

func TestShannonEntropy(t *testing.T) {
	assert.InDelta(t, 0.0, shannonEntropy(""), 0.001)
	assert.InDelta(t, 0.0, shannonEntropy("aaaa"), 0.001)
	// "abcd" -> 4 distinct equally-likely chars -> 2 bits/char.
	assert.InDelta(t, 2.0, shannonEntropy("abcd"), 0.001)
}
