// Package server provides the HTTP server implementation.
package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/loafoe/pico-agent/internal/observability"
	"github.com/loafoe/pico-agent/internal/spire"
	"github.com/loafoe/pico-agent/internal/task"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// Handlers holds HTTP handler dependencies.
type Handlers struct {
	registry             *task.Registry
	spireClient          *spire.Client
	metrics              *observability.Metrics
	version              string
	allowUnauthenticated bool
}

// NewHandlers creates a new handlers instance.
func NewHandlers(registry *task.Registry, spireClient *spire.Client, metrics *observability.Metrics, version string, allowUnauthenticated bool) *Handlers {
	return &Handlers{
		registry:             registry,
		spireClient:          spireClient,
		metrics:              metrics,
		version:              version,
		allowUnauthenticated: allowUnauthenticated,
	}
}

// authResult contains the result of an authentication attempt.
type authResult struct {
	authenticated bool
	rejected      bool // true if auth was attempted but failed (response already written)
}

// authenticate checks authentication using mTLS, JWT-SVID, or dev mode.
// Returns authResult indicating whether the request is authenticated or was rejected.
func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request, body []byte) authResult {
	ctx := r.Context()

	// 1. Check for mTLS (SPIRE X.509 SVID)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		slog.Debug("authenticated via mTLS", "remote_addr", r.RemoteAddr)
		h.metrics.RecordAuthAttempt("mtls", "success")
		return authResult{authenticated: true}
	}

	// 2. Check for JWT-SVID in Authorization header
	if h.spireClient != nil && h.spireClient.IsJWTEnabled() {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
			spiffeID, err := h.spireClient.ValidateJWTToken(ctx, authHeader)
			if err != nil {
				slog.Warn("JWT-SVID validation failed", "error", err, "remote_addr", r.RemoteAddr)
				h.metrics.RecordAuthAttempt("jwt", "rejected")
				h.writeError(w, http.StatusUnauthorized, "invalid JWT-SVID")
				return authResult{rejected: true}
			}
			slog.Debug("authenticated via JWT-SVID", "spiffe_id", spiffeID.String(), "remote_addr", r.RemoteAddr)
			h.metrics.RecordAuthAttempt("jwt", "success")
			return authResult{authenticated: true}
		}
	}

	// 3. Dev mode - allow unauthenticated if configured
	if h.allowUnauthenticated {
		slog.Debug("allowing unauthenticated request (dev mode)", "remote_addr", r.RemoteAddr)
		h.metrics.RecordAuthAttempt("dev", "success")
		return authResult{authenticated: true}
	}

	h.metrics.RecordAuthAttempt("none", "unauthenticated")
	return authResult{}
}

// requireAuth checks authentication and returns true if the request should proceed.
// If authentication fails, it writes an error response and returns false.
func (h *Handlers) requireAuth(w http.ResponseWriter, r *http.Request, body []byte) bool {
	result := h.authenticate(w, r, body)
	if result.rejected {
		return false
	}
	if !result.authenticated {
		slog.Warn("unauthenticated request rejected", "remote_addr", r.RemoteAddr)
		h.writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	return true
}

// HandleTask processes incoming task requests.
func (h *Handlers) HandleTask(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Only accept POST
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer func() { _ = r.Body.Close() }()

	// Authenticate
	if !h.requireAuth(w, r, body) {
		return
	}

	// Parse request
	req, err := task.ParseRequest(body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Execute task. The span is named after the task type and carries the
	// task type as an attribute so traces from pico-mcp can be filtered and
	// aggregated per task. Payload contents are deliberately not recorded as
	// they may contain sensitive data (e.g. ConfigMap values).
	ctx, span := observability.StartSpan(r.Context(), "task.execute "+req.Type)
	span.SetAttributes(attribute.String("pico_agent.task.type", req.Type))
	result, err := h.registry.Execute(ctx, *req)

	duration := time.Since(start).Seconds()

	if err != nil {
		observability.RecordError(span, err)
		span.End()
		slog.ErrorContext(ctx, "task execution failed", "type", req.Type, "error", err, "duration", duration)
		h.metrics.RecordTask(req.Type, "error", duration)
		h.writeError(w, http.StatusInternalServerError, "task execution failed")
		return
	}

	status := "success"
	if !result.Success {
		status = "failure"
	}
	span.SetAttributes(attribute.Bool("pico_agent.task.success", result.Success))
	if !result.Success {
		span.SetStatus(codes.Error, result.Error)
	}
	span.End()
	h.metrics.RecordTask(req.Type, status, duration)

	slog.InfoContext(ctx, "task completed", "type", req.Type, "success", result.Success, "duration", duration)
	h.writeJSON(w, http.StatusOK, result)
}

// HandleHealthz handles liveness probe requests.
func (h *Handlers) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// HandleInfo returns agent identity metadata for discovery/registration.
// This endpoint is unauthenticated — only exposes JWT audiences (public
// identifiers needed for callers to request correctly-scoped tokens).
func (h *Handlers) HandleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]any{}
	if h.spireClient != nil {
		if audiences := h.spireClient.JWTAudiences(); len(audiences) > 0 {
			info["jwt_audiences"] = audiences
		}
	}
	h.writeJSON(w, http.StatusOK, info)
}

// HandleReadyz handles readiness probe requests.
func (h *Handlers) HandleReadyz(w http.ResponseWriter, r *http.Request) {
	// Could add additional checks here (e.g., k8s connectivity)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// HandleListTasks returns the list of registered tasks.
func (h *Handlers) HandleListTasks(w http.ResponseWriter, r *http.Request) {
	// Authenticate (no body for GET requests)
	if !h.requireAuth(w, r, nil) {
		return
	}

	tasks := h.registry.List()
	h.writeJSON(w, http.StatusOK, map[string]any{
		"tasks": tasks,
	})
}

func (h *Handlers) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handlers) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, map[string]string{"error": message})
}

// HandleVersion returns the agent version.
func (h *Handlers) HandleVersion(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r, nil) {
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{
		"version": h.version,
	})
}
