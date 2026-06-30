package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/loafoe/centcom-satellite/internal/observability"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher interface for streaming support.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// LoggingMiddleware logs all HTTP requests.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		// Include trace/span IDs so access logs correlate with the
		// distributed trace originating from pico-mcp.
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.status,
			"duration", time.Since(start).String(),
			"remote_addr", r.RemoteAddr,
		}
		if sc := trace.SpanContextFromContext(r.Context()); sc.HasTraceID() {
			attrs = append(attrs, "trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String())
		}
		slog.Info("http request", attrs...)
	})
}

// knownRoutes is the fixed set of registered routes. Paths outside this set are
// bucketed to "other" to bound metric label cardinality (e.g. against 404-probing).
var knownRoutes = map[string]struct{}{
	"/task":        {},
	"/tasks":       {},
	"/healthz":     {},
	"/readyz":      {},
	"/version":     {},
	"/info":        {},
	"/logs/stream": {},
	"/metrics":     {},
}

// normalizeRoute maps a request path to a bounded label value.
func normalizeRoute(path string) string {
	if _, ok := knownRoutes[path]; ok {
		return path
	}
	return "other"
}

// MetricsMiddleware records HTTP metrics.
func MetricsMiddleware(metrics *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			metrics.HTTPRequestsInFlight.Inc()
			defer metrics.HTTPRequestsInFlight.Dec()

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start).Seconds()
			route := normalizeRoute(r.URL.Path)
			metrics.RecordHTTPRequest(r.Method, route, http.StatusText(wrapped.status), duration)
		})
	}
}

// TracingMiddleware extracts W3C trace context from incoming requests (injected
// by pico-mcp) and starts a server span for each request. It delegates to
// otelhttp so spans follow OpenTelemetry HTTP server semantic conventions
// (http.method, http.route, http.status_code, error status on 5xx) and use the
// globally configured propagator. The span is named by its matched route to
// keep span names low-cardinality.
func TracingMiddleware(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "http.server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + normalizeRoute(r.URL.Path)
		}),
	)
}

// RecoveryMiddleware recovers from panics and returns 500.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered", "error", err, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Chain applies middlewares to a handler in order.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
