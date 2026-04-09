// Package config handles application configuration loading and validation.
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/loafoe/pico-agent/internal/spire"
)

// Config holds all application configuration.
type Config struct {
	// Port is the main HTTP server port for the task endpoint.
	Port int

	// MetricsPort is the port for Prometheus metrics endpoint.
	MetricsPort int

	// WebhookSecret is the shared secret for HMAC signature verification.
	// When SPIRE is enabled, this becomes optional as mTLS provides authentication.
	WebhookSecret string

	// LogLevel controls logging verbosity (debug, info, warn, error).
	LogLevel string

	// LogFormat controls logging format (json, text).
	LogFormat string

	// OTelEndpoint is the OpenTelemetry collector endpoint (optional).
	OTelEndpoint string

	// OTelServiceName is the service name for tracing.
	OTelServiceName string

	// SPIRE holds SPIFFE/SPIRE configuration for workload identity.
	SPIRE spire.Config
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:            getEnvInt("PORT", 8080),
		MetricsPort:     getEnvInt("METRICS_PORT", 9090),
		WebhookSecret:   os.Getenv("WEBHOOK_SECRET"),
		LogLevel:        getEnvString("LOG_LEVEL", "info"),
		LogFormat:       getEnvString("LOG_FORMAT", "json"),
		OTelEndpoint:    os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		OTelServiceName: getEnvString("OTEL_SERVICE_NAME", "pico-agent"),
		SPIRE: spire.Config{
			Enabled:          getEnvBool("SPIRE_ENABLED", false),
			AgentSocket:      getEnvString("SPIRE_AGENT_SOCKET", "unix:///run/spire/agent/sockets/spire-agent.sock"),
			TrustDomains:     loadTrustDomains(),
			AllowedSPIFFEIDs: getEnvStringSlice("SPIRE_ALLOWED_SPIFFE_IDS"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that required configuration is present and valid.
func (c *Config) Validate() error {
	var errs []string

	// WebhookSecret is required unless SPIRE is enabled (mTLS provides auth)
	if c.WebhookSecret == "" && !c.SPIRE.Enabled {
		errs = append(errs, "WEBHOOK_SECRET is required (or enable SPIRE for mTLS auth)")
	}

	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, "PORT must be between 1 and 65535")
	}

	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		errs = append(errs, "METRICS_PORT must be between 1 and 65535")
	}

	if c.Port == c.MetricsPort {
		errs = append(errs, "PORT and METRICS_PORT must be different")
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(c.LogLevel)] {
		errs = append(errs, "LOG_LEVEL must be one of: debug, info, warn, error")
	}

	validLogFormats := map[string]bool{"json": true, "text": true}
	if !validLogFormats[strings.ToLower(c.LogFormat)] {
		errs = append(errs, "LOG_FORMAT must be one of: json, text")
	}

	// Validate SPIRE config
	if err := c.SPIRE.Validate(); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return errors.New("configuration errors: " + strings.Join(errs, "; "))
	}

	return nil
}

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		switch strings.ToLower(value) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string) []string {
	value := os.Getenv(key)
	if value == "" {
		return nil
	}
	// Split by comma and trim whitespace
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// loadTrustDomains loads SPIFFE trust domains from environment variables.
// Supports both SPIRE_TRUST_DOMAINS (comma-separated list) and
// SPIRE_TRUST_DOMAIN (single, for backward compatibility).
func loadTrustDomains() []string {
	// Prefer the new multi-domain variable
	if domains := getEnvStringSlice("SPIRE_TRUST_DOMAINS"); len(domains) > 0 {
		return domains
	}
	// Fall back to single trust domain for backward compatibility
	if domain := os.Getenv("SPIRE_TRUST_DOMAIN"); domain != "" {
		return []string{domain}
	}
	return nil
}
