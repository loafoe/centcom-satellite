package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheck_Matrix(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		value  string
		reason Reason
	}{
		// Safe config values pass through — this is the Cilium-WireGuard case.
		{"boolean flag", "enable-wireguard", "true", ""},
		{"cluster name", "cluster-name", "prod-eu", ""},
		{"port number", "listen-port", "8080", ""},
		{"short enum", "log-level", "info", ""},
		{"plain hostname", "endpoint", "loki.monitoring.svc", ""},

		// Secret-like key names redact regardless of value.
		{"password key", "db-password", "hunter2", ReasonSecretKeyName},
		{"token key", "bearer-token", "x", ReasonSecretKeyName},
		{"apikey underscore", "api_key", "abc", ReasonSecretKeyName},
		{"private key name", "tls-private-key", "...", ReasonSecretKeyName},
		{"credential key", "aws-credentials", "...", ReasonSecretKeyName},

		// PEM blocks redact.
		{"pem block", "ca", "-----BEGIN CERTIFICATE-----\nMIIB...", ReasonPEMBlock},

		// Inline secrets inside otherwise-innocent keys.
		{"connection string", "db-url", "postgres://u:p@h/d?password=s3cr3t", ReasonInlineSecret},
		{"env dump", "config", "DEBUG=true\nAPI_TOKEN=abcdef", ReasonInlineSecret},

		// High-entropy long strings redact; long-but-structured stays.
		{"random token", "data", "aB3xY9zQw7Lp2Km5Nv8Rt4Hs6Jd0Fg1", ReasonHighEntropy},
		{"long english prose", "notes", "this is a perfectly ordinary sentence of config documentation", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reason, Check(tt.key, tt.value),
				"key=%q value=%q", tt.key, tt.value)
		})
	}
}

func TestCheck_EntropyLengthBoundary(t *testing.T) {
	// A high-entropy string of exactly minEntropyLen (20) chars is evaluated;
	// one char shorter is exempt from the entropy heuristic.
	high20 := "aB3xY9zQw7Lp2Km5Nv8R" // 20 chars, high entropy
	assert.Equal(t, ReasonHighEntropy, Check("data", high20))
	assert.Len(t, high20, minEntropyLen)

	high19 := "aB3xY9zQw7Lp2Km5Nv8" // 19 chars
	assert.Equal(t, Reason(""), Check("data", high19),
		"values shorter than minEntropyLen are exempt from the entropy heuristic")
}

func TestShannonEntropy(t *testing.T) {
	assert.InDelta(t, 0.0, ShannonEntropy(""), 0.001)
	assert.InDelta(t, 0.0, ShannonEntropy("aaaa"), 0.001)
	// "abcd" -> 4 distinct equally-likely chars -> 2 bits/char.
	assert.InDelta(t, 2.0, ShannonEntropy("abcd"), 0.001)
}
