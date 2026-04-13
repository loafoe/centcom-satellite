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
}

// NewHandlers creates a new handlers instance.
func NewHandlers(registry *task.Registry, verifier *webhook.Verifier, spireClient *spire.Client, metrics *observability.Metrics) *Handlers {
	return &Handlers{
		registry:    registry,
		verifier:    verifier,
		spireClient: spireClient,
		metrics:     metrics,
	}
}

// HandleTask processes incoming task requests.
func (h *Handlers) HandleTask(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	defer r.Body.Close()

	// Authentication: try methods in order of preference
	authenticated := false

	// 1. Check for mTLS (SPIRE X.509 SVID) - already validated at TLS layer
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		authenticated = true
		slog.Debug("authenticated via mTLS", "remote_addr", r.RemoteAddr)
	}

	// 2. Check for JWT-SVID in Authorization header
	if !authenticated && h.spireClient != nil && h.spireClient.IsJWTEnabled() {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
			spiffeID, err := h.spireClient.ValidateJWTToken(ctx, authHeader)
			if err != nil {
				slog.Warn("JWT-SVID validation failed", "error", err, "remote_addr", r.RemoteAddr)
				h.writeError(w, http.StatusUnauthorized, "invalid JWT-SVID")
				return
			}
			authenticated = true
			slog.Debug("authenticated via JWT-SVID", "spiffe_id", spiffeID.String(), "remote_addr", r.RemoteAddr)
		}
	}

	// 3. Check for webhook signature
	if !authenticated && h.verifier != nil {
		signature := r.Header.Get(webhook.SignatureHeader)
		if signature != "" {
			if err := h.verifier.Verify(signature, body); err != nil {
				slog.Warn("signature verification failed", "error", err, "remote_addr", r.RemoteAddr)
				h.writeError(w, http.StatusUnauthorized, "invalid signature")
				return
			}
			authenticated = true
			slog.Debug("authenticated via webhook signature", "remote_addr", r.RemoteAddr)
		}
	}

	// No valid authentication found
	if !authenticated {
		slog.Warn("unauthenticated request rejected", "remote_addr", r.RemoteAddr)
		h.writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Parse request
	req, err := task.ParseRequest(body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Execute task
	ctx, span := observability.StartSpan(ctx, "task.execute")
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
