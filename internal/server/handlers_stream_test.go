package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/loafoe/centcom-satellite/internal/observability"
)

func TestHandleLogStream_NoClientsetConfigured(t *testing.T) {
	metrics := observability.NewMetricsWithRegistry(prometheus.NewRegistry())
	h := NewStreamHandlers(nil, nil, metrics, true)

	req := httptest.NewRequest(http.MethodGet, "/logs/stream?namespace=default&pod=test-pod", nil)
	w := httptest.NewRecorder()
	h.HandleLogStream(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
