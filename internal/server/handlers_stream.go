// Package server provides HTTP handlers including log streaming.
package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/spire"
)

// LogLine represents a single log line in the stream.
type LogLine struct {
	Timestamp time.Time `json:"ts"`
	Line      string    `json:"line"`
}

// StreamHandlers holds dependencies for streaming endpoints.
type StreamHandlers struct {
	clientset            kubernetes.Interface
	spireClient          *spire.Client
	allowUnauthenticated bool
}

// NewStreamHandlers creates a new StreamHandlers instance.
func NewStreamHandlers(clientset kubernetes.Interface, spireClient *spire.Client, allowUnauthenticated bool) *StreamHandlers {
	return &StreamHandlers{
		clientset:            clientset,
		spireClient:          spireClient,
		allowUnauthenticated: allowUnauthenticated,
	}
}

// authenticate checks authentication for streaming endpoints.
func (h *StreamHandlers) authenticate(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()

	// 1. Check for mTLS (SPIRE X.509 SVID)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		slog.Debug("stream authenticated via mTLS", "remote_addr", r.RemoteAddr)
		return true
	}

	// 2. Check for JWT-SVID in Authorization header
	if h.spireClient != nil && h.spireClient.IsJWTEnabled() {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
			spiffeID, err := h.spireClient.ValidateJWTToken(ctx, authHeader)
			if err != nil {
				slog.Warn("stream JWT-SVID validation failed", "error", err, "remote_addr", r.RemoteAddr)
				http.Error(w, "invalid JWT-SVID", http.StatusUnauthorized)
				return false
			}
			slog.Debug("stream authenticated via JWT-SVID", "spiffe_id", spiffeID.String(), "remote_addr", r.RemoteAddr)
			return true
		}
	}

	// 3. Dev mode - allow unauthenticated if configured
	if h.allowUnauthenticated {
		slog.Debug("stream allowing unauthenticated request (dev mode)", "remote_addr", r.RemoteAddr)
		return true
	}

	slog.Warn("stream unauthenticated request rejected", "remote_addr", r.RemoteAddr)
	http.Error(w, "authentication required", http.StatusUnauthorized)
	return false
}

// HandleLogStream streams pod logs using chunked transfer encoding with NDJSON.
// GET /logs/stream?namespace=X&pod=Y&container=Z&tail=100
func (h *StreamHandlers) HandleLogStream(w http.ResponseWriter, r *http.Request) {
	// Only accept GET
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate
	if !h.authenticate(w, r) {
		return
	}

	// Parse query parameters
	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("pod")
	container := r.URL.Query().Get("container")
	tailStr := r.URL.Query().Get("tail")

	if namespace == "" || podName == "" {
		http.Error(w, "namespace and pod are required", http.StatusBadRequest)
		return
	}

	tailLines := int64(100)
	if tailStr != "" {
		if parsed, err := strconv.ParseInt(tailStr, 10, 64); err == nil && parsed > 0 {
			tailLines = parsed
		}
	}

	// Get pod to verify it exists and determine container
	ctx := r.Context()
	pod, err := h.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		slog.Error("failed to get pod", "namespace", namespace, "pod", podName, "error", err)
		http.Error(w, fmt.Sprintf("failed to get pod: %v", err), http.StatusNotFound)
		return
	}

	// Determine container name
	containerName := container
	if containerName == "" {
		if len(pod.Spec.Containers) == 0 {
			http.Error(w, "pod has no containers", http.StatusBadRequest)
			return
		}
		containerName = pod.Spec.Containers[0].Name
	}

	// Build log options with Follow enabled
	opts := &corev1.PodLogOptions{
		Container:  containerName,
		Follow:     true,
		Timestamps: true,
		TailLines:  &tailLines,
	}

	// Get log stream
	stream, err := h.clientset.CoreV1().Pods(namespace).GetLogs(podName, opts).Stream(ctx)
	if err != nil {
		slog.Error("failed to get log stream", "namespace", namespace, "pod", podName, "error", err)
		http.Error(w, fmt.Sprintf("failed to get log stream: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() { _ = stream.Close() }()

	// Set headers for chunked streaming
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Get flusher for streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	slog.Info("starting log stream", "namespace", namespace, "pod", podName, "container", containerName)

	// Stream logs line by line
	scanner := bufio.NewScanner(stream)
	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	encoder := json.NewEncoder(w)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			slog.Info("log stream context cancelled", "namespace", namespace, "pod", podName)
			return
		default:
		}

		line := scanner.Text()
		ts, logLine := parseTimestampedLine(line)

		logEntry := LogLine{
			Timestamp: ts,
			Line:      logLine,
		}

		if err := encoder.Encode(logEntry); err != nil {
			slog.Debug("failed to encode log line, client likely disconnected", "error", err)
			return
		}
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		// Don't log errors for context cancellation (normal disconnect)
		if ctx.Err() == nil {
			slog.Error("log stream scanner error", "error", err)
		}
	}

	slog.Info("log stream ended", "namespace", namespace, "pod", podName)
}

// parseTimestampedLine splits a k8s timestamped log line into timestamp and content.
// Format: "2006-01-02T15:04:05.999999999Z <log content>"
func parseTimestampedLine(line string) (time.Time, string) {
	// K8s timestamps are RFC3339Nano format, always 30 chars + space
	if len(line) > 31 && line[30] == ' ' {
		if ts, err := time.Parse(time.RFC3339Nano, line[:30]); err == nil {
			return ts, line[31:]
		}
	}
	// Fallback: try shorter timestamp format or return current time
	if len(line) > 20 && (line[19] == 'Z' || line[19] == ' ') {
		if ts, err := time.Parse(time.RFC3339, line[:20]); err == nil {
			if len(line) > 21 {
				return ts, line[21:]
			}
			return ts, ""
		}
	}
	return time.Now(), line
}
