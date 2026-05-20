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

	// AllowUnauthenticated allows requests without authentication.
	// Only for local development - do not enable in production.
	AllowUnauthenticated bool

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

	// Features holds feature flags for optional functionality.
	Features FeaturesConfig
}

// FeaturesConfig holds feature flags.
type FeaturesConfig struct {
	// GetResourceEnabled enables the get_resource task for fetching arbitrary resources.
	// Disabled by default as it requires expanded RBAC permissions.
	GetResourceEnabled bool

	// WorkloadRestartEnabled enables the workload_restart task for restarting workloads.
	// Disabled by default as it requires write permissions and can cause service disruption.
	WorkloadRestartEnabled bool

	// WorkloadScaleEnabled enables the workload_scale task for scaling workloads.
	// Disabled by default as it requires write permissions and can impact cluster resources.
	WorkloadScaleEnabled bool

	// PodEvictEnabled enables the pod_evict task for evicting pods.
	// Disabled by default as it requires write permissions and can cause service disruption.
	PodEvictEnabled bool

	// PodResizeEnabled enables the pod_resize task for in-place memory resize.
	// Disabled by default as it requires write permissions and K8s 1.27+.
	PodResizeEnabled bool

	// PodResizeConfig holds configuration for the pod_resize task.
	PodResizeConfig PodResizeConfig

	// NodeclaimDeleteEnabled enables the nodeclaim_delete task for Karpenter node management.
	// Disabled by default as it requires Karpenter and can cause node termination.
	NodeclaimDeleteEnabled bool

	// ArgocdEnabled enables the list_argocd_applications task for Argo CD introspection.
	// Disabled by default as it requires Argo CD CRDs and RBAC for argoproj.io.
	ArgocdEnabled bool

	// HTTPRequestEnabled enables the http_request task for making HTTP requests to cluster-internal services.
	// Disabled by default as it allows arbitrary HTTP requests within the cluster.
	HTTPRequestEnabled bool
}

// PodResizeConfig holds pod_resize task configuration.
type PodResizeConfig struct {
	// PercentageCap is the maximum percentage increase allowed (default 50).
	PercentageCap int
	// AbsoluteCap is the maximum memory value allowed (default "8Gi").
	AbsoluteCap string
	// ShrinkBuffer is the safety buffer percentage above current usage when reducing limits (default 20).
	ShrinkBuffer int
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:                 getEnvInt("PORT", 8080),
		MetricsPort:          getEnvInt("METRICS_PORT", 9090),
		AllowUnauthenticated: getEnvBool("ALLOW_UNAUTHENTICATED", false),
		LogLevel:             getEnvString("LOG_LEVEL", "info"),
		LogFormat:            getEnvString("LOG_FORMAT", "json"),
		OTelEndpoint:         os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		OTelServiceName:      getEnvString("OTEL_SERVICE_NAME", "pico-agent"),
		SPIRE: spire.Config{
			Enabled:          getEnvBool("SPIRE_ENABLED", false),
			AgentSocket:      getEnvString("SPIRE_AGENT_SOCKET", "unix:///run/spire/agent/sockets/spire-agent.sock"),
			TrustDomains:     loadTrustDomains(),
			AllowedSPIFFEIDs: getEnvStringSlice("SPIRE_ALLOWED_SPIFFE_IDS"),
			MTLSEnabled:      getEnvBool("SPIRE_MTLS_ENABLED", false),
			JWT: spire.JWTConfig{
				Enabled:   getEnvBool("SPIRE_JWT_ENABLED", false),
				Audiences: getEnvStringSlice("SPIRE_JWT_AUDIENCES"),
			},
		},
		Features: FeaturesConfig{
			GetResourceEnabled:     getEnvBool("GET_RESOURCE_ENABLED", false),
			WorkloadRestartEnabled: getEnvBool("WORKLOAD_RESTART_ENABLED", false),
			WorkloadScaleEnabled:   getEnvBool("WORKLOAD_SCALE_ENABLED", false),
			PodEvictEnabled:        getEnvBool("POD_EVICT_ENABLED", false),
			PodResizeEnabled:       getEnvBool("POD_RESIZE_ENABLED", false),
			PodResizeConfig: PodResizeConfig{
				PercentageCap: getEnvInt("POD_RESIZE_PERCENTAGE_CAP", 50),
				AbsoluteCap:   getEnvString("POD_RESIZE_ABSOLUTE_CAP", "8Gi"),
				ShrinkBuffer:  getEnvInt("POD_RESIZE_SHRINK_BUFFER", 20),
			},
			NodeclaimDeleteEnabled: getEnvBool("NODECLAIM_DELETE_ENABLED", false),
			ArgocdEnabled:          getEnvBool("FEATURES_ARGOCD", false),
			HTTPRequestEnabled:     getEnvBool("HTTP_REQUEST_ENABLED", false),
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

	// Either SPIRE must be enabled or AllowUnauthenticated must be true
	if !c.SPIRE.Enabled && !c.AllowUnauthenticated {
		errs = append(errs, "SPIRE must be enabled or ALLOW_UNAUTHENTICATED must be set to true")
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
