package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/loafoe/pico-agent/internal/observability"
	"github.com/loafoe/pico-agent/internal/task"
	"github.com/loafoe/pico-agent/internal/webhook"
)

// mockTask implements task.Task for testing.
type mockTask struct {
	name   string
	result *task.Result
	err    error
}

func (m *mockTask) Name() string {
	return m.name
}

func (m *mockTask) Execute(_ context.Context, _ json.RawMessage) (*task.Result, error) {
	return m.result, m.err
}

func setupTestHandlers(t *testing.T) (*Handlers, *webhook.Verifier) {
	t.Helper()
	registry := task.NewRegistry()
	registry.Register(&mockTask{
		name:   "test_task",
		result: task.NewSuccessResult("done"),
	})

	verifier := webhook.NewVerifier("test-secret")
	// Use a fresh registry for each test to avoid duplicate registration
	metrics := observability.NewMetricsWithRegistry(prometheus.NewRegistry())

	return NewHandlers(registry, verifier, nil, metrics), verifier
}

func TestHandleTask_Success(t *testing.T) {
	handlers, verifier := setupTestHandlers(t)

	payload := []byte(`{"type":"test_task","payload":{}}`)
	signature := verifier.Sign(payload)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))
	req.Header.Set(webhook.SignatureHeader, signature)

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var result task.Result
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Success {
		t.Error("expected success=true")
	}
}

func TestHandleTask_MethodNotAllowed(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/task", nil)
	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestHandleTask_InvalidSignature(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	payload := []byte(`{"type":"test_task","payload":{}}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))
	req.Header.Set(webhook.SignatureHeader, "sha256=invalid")

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleTask_MissingSignature(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	payload := []byte(`{"type":"test_task","payload":{}}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))
	// No signature header

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleTask_InvalidJSON(t *testing.T) {
	handlers, verifier := setupTestHandlers(t)

	payload := []byte(`{invalid json}`)
	signature := verifier.Sign(payload)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))
	req.Header.Set(webhook.SignatureHeader, signature)

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestHandleTask_UnknownTaskType(t *testing.T) {
	handlers, verifier := setupTestHandlers(t)

	payload := []byte(`{"type":"unknown_task","payload":{}}`)
	signature := verifier.Sign(payload)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))
	req.Header.Set(webhook.SignatureHeader, signature)

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestHandleHealthz(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handlers.HandleHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if rec.Body.String() != "ok" {
		t.Errorf("expected body 'ok', got %q", rec.Body.String())
	}
}

func TestHandleReadyz(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handlers.HandleReadyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestHandleListTasks_Unauthenticated(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/tasks", nil)
	rec := httptest.NewRecorder()
	handlers.HandleListTasks(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleListTasks_WithMTLS(t *testing.T) {
	handlers, _ := setupTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/tasks", nil)
	// Simulate mTLS by setting TLS with peer certificates
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
	}
	rec := httptest.NewRecorder()
	handlers.HandleListTasks(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tasks, ok := response["tasks"].([]interface{})
	if !ok {
		t.Fatal("expected tasks array in response")
	}

	if len(tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(tasks))
	}
}
