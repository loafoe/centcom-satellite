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

func setupTestHandlers(t *testing.T, allowUnauthenticated bool) *Handlers {
	t.Helper()
	registry := task.NewRegistry()
	registry.Register(&mockTask{
		name:   "test_task",
		result: task.NewSuccessResult("done"),
	})

	// Use a fresh registry for each test to avoid duplicate registration
	metrics := observability.NewMetricsWithRegistry(prometheus.NewRegistry())

	return NewHandlers(registry, nil, metrics, "test-version", allowUnauthenticated)
}

func TestHandleTask_Success(t *testing.T) {
	handlers := setupTestHandlers(t, true)

	payload := []byte(`{"type":"test_task","payload":{}}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))

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
	handlers := setupTestHandlers(t, true)

	req := httptest.NewRequest(http.MethodGet, "/task", nil)
	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestHandleTask_Unauthenticated(t *testing.T) {
	handlers := setupTestHandlers(t, false)

	payload := []byte(`{"type":"test_task","payload":{}}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleTask_AllowUnauthenticated(t *testing.T) {
	handlers := setupTestHandlers(t, true)

	payload := []byte(`{"type":"test_task","payload":{}}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestHandleTask_InvalidJSON(t *testing.T) {
	handlers := setupTestHandlers(t, true)

	payload := []byte(`{invalid json}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestHandleTask_UnknownTaskType(t *testing.T) {
	handlers := setupTestHandlers(t, true)

	payload := []byte(`{"type":"unknown_task","payload":{}}`)

	req := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(payload))

	rec := httptest.NewRecorder()
	handlers.HandleTask(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestHandleHealthz(t *testing.T) {
	handlers := setupTestHandlers(t, true)

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
	handlers := setupTestHandlers(t, true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handlers.HandleReadyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestHandleListTasks_Unauthenticated(t *testing.T) {
	handlers := setupTestHandlers(t, false)

	req := httptest.NewRequest(http.MethodGet, "/tasks", nil)
	rec := httptest.NewRecorder()
	handlers.HandleListTasks(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestHandleListTasks_WithMTLS(t *testing.T) {
	handlers := setupTestHandlers(t, false)

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
