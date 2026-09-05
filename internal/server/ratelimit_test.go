package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/loafoe/centcom-satellite/internal/config"
)

func newTestHandler(cfg config.RateLimitConfig) http.Handler {
	return RateLimitMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func doRequest(t *testing.T, h http.Handler, path, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestRateLimitMiddleware_AllowsWithinBurst(t *testing.T) {
	h := newTestHandler(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 2, Burst: 3})
	for i := 0; i < 3; i++ {
		rr := doRequest(t, h, "/task", "10.0.0.1:12345")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i+1, rr.Code)
		}
	}
}

func TestRateLimitMiddleware_RejectsOverBurstWithHeaders(t *testing.T) {
	h := newTestHandler(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 2, Burst: 3})
	for i := 0; i < 3; i++ {
		doRequest(t, h, "/task", "10.0.0.1:12345")
	}

	rr := doRequest(t, h, "/task", "10.0.0.1:12345")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
	if got := rr.Header().Get("RateLimit-Limit"); got != "3" {
		t.Errorf("RateLimit-Limit = %q, want %q", got, "3")
	}
	if got := rr.Header().Get("RateLimit-Remaining"); got != "0" {
		t.Errorf("RateLimit-Remaining = %q, want %q", got, "0")
	}
	if rr.Header().Get("RateLimit-Reset") == "" {
		t.Error("missing RateLimit-Reset header")
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rr.Header().Get("Content-Type"))
	}
}

func TestRateLimitMiddleware_PerIPIsolation(t *testing.T) {
	h := newTestHandler(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 2, Burst: 1})
	doRequest(t, h, "/task", "10.0.0.1:1") // exhausts 10.0.0.1's single-token burst

	rrSame := doRequest(t, h, "/task", "10.0.0.1:2") // same IP, different port -> same bucket
	if rrSame.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP different port: got %d, want 429", rrSame.Code)
	}

	rrOther := doRequest(t, h, "/task", "10.0.0.2:1")
	if rrOther.Code != http.StatusOK {
		t.Fatalf("different IP: got %d, want 200", rrOther.Code)
	}
}

func TestRateLimitMiddleware_HealthEndpointsNeverLimited(t *testing.T) {
	h := newTestHandler(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})
	doRequest(t, h, "/healthz", "10.0.0.1:1") // exhaust the burst via a non-exempt path first
	for i := 0; i < 5; i++ {
		if rr := doRequest(t, h, "/healthz", "10.0.0.1:1"); rr.Code != http.StatusOK {
			t.Fatalf("/healthz request %d: got %d, want 200", i, rr.Code)
		}
		if rr := doRequest(t, h, "/readyz", "10.0.0.1:1"); rr.Code != http.StatusOK {
			t.Fatalf("/readyz request %d: got %d, want 200", i, rr.Code)
		}
	}
}

func TestRateLimitMiddleware_RecoversAfterRetryAfter(t *testing.T) {
	h := newTestHandler(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 5, Burst: 1})
	doRequest(t, h, "/task", "10.0.0.1:1")
	rr := doRequest(t, h, "/task", "10.0.0.1:1")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rr.Code)
	}

	time.Sleep(250 * time.Millisecond) // rps=5 -> one token every 200ms
	rr2 := doRequest(t, h, "/task", "10.0.0.1:1")
	if rr2.Code != http.StatusOK {
		t.Fatalf("after waiting: got %d, want 200", rr2.Code)
	}
}

func TestRateLimitMiddleware_DisabledPassesEverythingThrough(t *testing.T) {
	h := newTestHandler(config.RateLimitConfig{Enabled: false})
	for i := 0; i < 20; i++ {
		if rr := doRequest(t, h, "/task", "10.0.0.1:1"); rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200 (limiter disabled)", i, rr.Code)
		}
	}
}
