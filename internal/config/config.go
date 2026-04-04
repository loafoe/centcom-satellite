// Package config handles application configuration loading and validation.
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration.
type Config struct {
	// Port is the main HTTP server port for the task endpoint.
	Port int

	// MetricsPort is the port for Prometheus metrics endpoint.
	MetricsPort int

	// WebhookSecret is the shared secret for HMAC signature verification.
	WebhookSecret string

	// LogLevel controls logging verbosity (debug, info, warn, error).
	LogLevel string

	// LogFormat controls logging format (json, text).
	LogFormat string

	// OTelEndpoint is the OpenTelemetry collector endpoint (optional).
	OTelEndpoint string

	// OTelServiceName is the service name for tracing.
	OTelServiceName string
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
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that required configuration is present and valid.
func (c *Config) Validate() error {
	var errs []string

	if c.WebhookSecret == "" {
		errs = append(errs, "WEBHOOK_SECRET is required")
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
