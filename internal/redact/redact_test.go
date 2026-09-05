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

		// HCL/Alloy-style config-language syntax must NOT be mistaken for an
		// inline secret: a boolean flag whose key happens to contain "secret",
		// and a bare dotted attribute reference to another block's exported
		// value (the actual secret, if any, lives wherever that reference
		// points - e.g. a mounted file - never inlined in this text).
		{"secret-named boolean flag", "config", "is_secret = true", ""},
		{"dotted attribute reference", "config", "token = local.file.spiffe_jwt.content", ""},
		{"mixed: reference plus real literal still redacts", "config", "token = local.file.spiffe_jwt.content\npassword = hunter2", ReasonInlineSecret},

		// High-entropy long strings redact; long-but-structured stays.
		{"random token", "data", "aB3xY9zQw7Lp2Km5Nv8Rt4Hs6Jd0Fg1", ReasonHighEntropy},
		{"long english prose", "notes", "this is a perfectly ordinary sentence of config documentation", ""},

		// Calibration regression set (2026-09-05, real Grafana Alloy ConfigMap
		// false-positive investigation): benign structured technical tokens
		// commonly land at 4.0-4.3 bits/char and must stay exempt, while
		// genuinely secret-shaped tokens (4.5+) must still redact. See
		// entropyThreshold's doc comment for the full calibration rationale.
		{"https URL (benign, 4.27 bits/char)", "endpoint", `"https://otlp-gateway.ri-obs-use1-ct.hsp.philips.com"`, ""},
		{"dotted attribute path (benign, 4.03 bits/char)", "data", "discovery.relabel.kube_state_metrics.output", ""},
		{"OTTL expression (benign, 4.13 bits/char)", "data", `set(attributes["k8s.cluster.name"], "x")`, ""},
		{"AWS-style secret key (real secret, 4.66 bits/char)", "config", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ReasonHighEntropy},
		{"grafana-style service token (real secret, 4.58 bits/char)", "config", "glsa_1234567890abcdefABCDEF1234567890abcdefAB_1a2b3c4d", ReasonHighEntropy},
		{"JWT (real secret, 5.33 bits/char)", "config", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", ReasonHighEntropy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reason, Check(tt.key, tt.value),
				"key=%q value=%q", tt.key, tt.value)
		})
	}
}

func TestCheck_EntropyLengthBoundary(t *testing.T) {
	// A high-entropy string of exactly minEntropyLen (24) chars is evaluated;
	// one char shorter is exempt from the entropy heuristic.
	high24 := "aB3xY9zQw7Lp2Km5Nv8Rt4Hs" // 24 chars, high entropy
	assert.Equal(t, ReasonHighEntropy, Check("data", high24))
	assert.Len(t, high24, minEntropyLen)

	high23 := "aB3xY9zQw7Lp2Km5Nv8Rt4H" // 23 chars
	assert.Equal(t, Reason(""), Check("data", high23),
		"values shorter than minEntropyLen are exempt from the entropy heuristic")
}

func TestShannonEntropy(t *testing.T) {
	assert.InDelta(t, 0.0, ShannonEntropy(""), 0.001)
	assert.InDelta(t, 0.0, ShannonEntropy("aaaa"), 0.001)
	// "abcd" -> 4 distinct equally-likely chars -> 2 bits/char.
	assert.InDelta(t, 2.0, ShannonEntropy("abcd"), 0.001)
}
