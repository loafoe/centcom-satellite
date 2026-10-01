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

		// No entropy heuristic: long, random-looking, or technical-looking
		// strings pass through untouched unless they match one of the exact
		// patterns above. See the package doc comment for why a "looks
		// random" heuristic was removed entirely - it caused active harm.
		{"random-looking token, no secret-shaped key or pattern", "data", "aB3xY9zQw7Lp2Km5Nv8Rt4Hs6Jd0Fg1", ""},
		{"long english prose", "notes", "this is a perfectly ordinary sentence of config documentation", ""},
		{"https URL", "endpoint", `"https://otlp-gateway.ri-obs-use1-ct.hsp.philips.com"`, ""},
		{"dotted attribute path", "data", "discovery.relabel.kube_state_metrics.output", ""},
		{"OTTL expression", "data", `set(attributes["k8s.cluster.name"], "x")`, ""},
		{"AWS-style secret key under a benign key name - not caught, by design", "config", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""},
		{"JWT under a benign key name - not caught, by design", "config", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.reason, Check(tt.key, tt.value),
				"key=%q value=%q", tt.key, tt.value)
		})
	}
}
