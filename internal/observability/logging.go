// Package observability provides metrics, tracing, and logging setup.
package observability

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

// SetupLogging configures the global slog logger.
//
// The handler is wrapped so that any log emitted with a context carrying an
// active span (i.e. via slog.InfoContext/ErrorContext/etc.) is automatically
// annotated with trace_id and span_id. This correlates pico-agent logs with
// the distributed trace that originates in pico-mcp, so an operator can pivot
// from a log line to the full trace and back.
func SetupLogging(level, format string) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}

	var out io.Writer = os.Stdout

	switch strings.ToLower(format) {
	case "text":
		handler = slog.NewTextHandler(out, opts)
	default:
		handler = slog.NewJSONHandler(out, opts)
	}

	logger := slog.New(&traceHandler{next: handler})
	slog.SetDefault(logger)
}

// traceHandler decorates log records with trace correlation fields extracted
// from the record's context. It is a thin pass-through for every other slog
// handler responsibility.
type traceHandler struct {
	next slog.Handler
}

func (h *traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *traceHandler) Handle(ctx context.Context, record slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		record.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.next.Handle(ctx, record)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{next: h.next.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{next: h.next.WithGroup(name)}
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
