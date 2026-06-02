package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/loafoe/pico-agent/internal/observability"
	"github.com/loafoe/pico-agent/internal/task"
)

// TestMetricsEndToEnd wires the real middleware chain to the task handler and
// scrapes a promhttp endpoint backed by the same registry, confirming HTTP,
// task, and auth metrics are emitted with a normalized route label.
func TestMetricsEndToEnd(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := observability.NewMetricsWithRegistry(reg)

	registry := task.NewRegistry()
	registry.Register(&mockTask{name: "test_task", result: task.NewSuccessResult("done")})
	h := NewHandlers(registry, nil, metrics, "test", true /* allowUnauthenticated */)

	mux := http.NewServeMux()
	mux.HandleFunc("/task", h.HandleTask)
	handler := Chain(mux, RecoveryMiddleware, MetricsMiddleware(metrics), LoggingMiddleware)

	// Exercise a known route and an unknown route (should bucket to "other").
	for _, path := range []string{"/task", "/does-not-exist"} {
		var body io.Reader
		method := http.MethodGet
		if path == "/task" {
			method = http.MethodPost
			body = bytes.NewReader([]byte(`{"type":"test_task","payload":{}}`))
		}
		req := httptest.NewRequest(method, path, body)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Scrape /metrics from the same registry.
	scrape := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer scrape.Close()

	resp, err := http.Get(scrape.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := string(raw)

	wantSubstrings := []string{
		`pico_agent_http_requests_total{method="POST",path="/task",status="OK"} 1`,
		`path="other"`, // the unknown route was bucketed
		`pico_agent_tasks_total{status="success",type="test_task"} 1`,
		`pico_agent_auth_attempts_total{method="dev",result="success"} 1`,
		`pico_agent_http_requests_in_flight 0`, // both requests finished
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n--- got ---\n%s", want, out)
		}
	}
}
