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
	"github.com/loafoe/pico-agent/internal/webhook"
)

// Handlers holds HTTP handler dependencies.
type Handlers struct {
	registry    *task.Registry
	verifier    *webhook.Verifier
	spireClient *spire.Client
	metrics     *observability.Metrics
	version     string
}

// NewHandlers creates a new handlers instance.
func NewHandlers(registry *task.Registry, verifier *webhook.Verifier, spireClient *spire.Client, metrics *observability.Metrics, version string) *Handlers {
	return &Handlers{
		registry:    registry,
		verifier:    verifier,
		spireClient: spireClient,
		metrics:     metrics,
		version:     version,
	}
}

// authResult contains the result of an authentication attempt.
type authResult struct {
	authenticated bool
	rejected      bool // true if auth was attempted but failed (response already written)
}

// authenticate checks authentication using mTLS, JWT-SVID, or webhook signature.
// If body is provided, webhook signature verification is attempted.
// Returns authResult indicating whether the request is authenticated or was rejected.
func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request, body []byte) authResult {
	ctx := r.Context()

	// 1. Check for mTLS (SPIRE X.509 SVID) - already validated at TLS layer
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		slog.Debug("authenticated via mTLS", "remote_addr", r.RemoteAddr)
		return authResult{authenticated: true}
	}

	// 2. Check for JWT-SVID in Authorization header
	if h.spireClient != nil && h.spireClient.IsJWTEnabled() {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
			spiffeID, err := h.spireClient.ValidateJWTToken(ctx, authHeader)
			if err != nil {
				slog.Warn("JWT-SVID validation failed", "error", err, "remote_addr", r.RemoteAddr)
				h.writeError(w, http.StatusUnauthorized, "invalid JWT-SVID")
				return authResult{rejected: true}
			}
			slog.Debug("authenticated via JWT-SVID", "spiffe_id", spiffeID.String(), "remote_addr", r.RemoteAddr)
			return authResult{authenticated: true}
		}
	}

	// 3. Check for webhook signature (only if body is provided)
	if body != nil && h.verifier != nil {
		signature := r.Header.Get(webhook.SignatureHeader)
		if signature != "" {
			if err := h.verifier.Verify(signature, body); err != nil {
				slog.Warn("signature verification failed", "error", err, "remote_addr", r.RemoteAddr)
				h.writeError(w, http.StatusUnauthorized, "invalid signature")
				return authResult{rejected: true}
			}
			slog.Debug("authenticated via webhook signature", "remote_addr", r.RemoteAddr)
			return authResult{authenticated: true}
		}
	}

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

	// Execute task
	ctx, span := observability.StartSpan(r.Context(), "task.execute")
	result, err := h.registry.Execute(ctx, *req)
	span.End()

	duration := time.Since(start).Seconds()

	if err != nil {
		slog.Error("task execution failed", "type", req.Type, "error", err, "duration", duration)
		h.metrics.RecordTask(req.Type, "error", duration)
		h.writeError(w, http.StatusInternalServerError, "task execution failed")
		return
	}

	status := "success"
	if !result.Success {
		status = "failure"
	}
	h.metrics.RecordTask(req.Type, status, duration)

	slog.Info("task completed", "type", req.Type, "success", result.Success, "duration", duration)
	h.writeJSON(w, http.StatusOK, result)
}

// HandleHealthz handles liveness probe requests.
func (h *Handlers) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
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
