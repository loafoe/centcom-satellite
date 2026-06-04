package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

// newTraceLogger builds a logger using the trace-correlating handler writing
// JSON to buf, mirroring the production setup in SetupLogging.
func newTraceLogger(buf *bytes.Buffer) *slog.Logger {
	base := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(&traceHandler{next: base})
}

func TestTraceHandlerInjectsTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	logger := newTraceLogger(&buf)

	traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("failed to parse log line: %v", err)
	}
	if got := rec["trace_id"]; got != traceID.String() {
		t.Errorf("trace_id = %v, want %v", got, traceID.String())
	}
	if got := rec["span_id"]; got != spanID.String() {
		t.Errorf("span_id = %v, want %v", got, spanID.String())
	}
}

func TestTraceHandlerNoSpanNoFields(t *testing.T) {
	var buf bytes.Buffer
	logger := newTraceLogger(&buf)

	logger.InfoContext(context.Background(), "hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("failed to parse log line: %v", err)
	}
	if _, ok := rec["trace_id"]; ok {
		t.Error("trace_id should be absent when no span is present")
	}
	if _, ok := rec["span_id"]; ok {
		t.Error("span_id should be absent when no span is present")
	}
}

func TestTraceHandlerPreservesAttrsAndGroups(t *testing.T) {
	var buf bytes.Buffer
	logger := newTraceLogger(&buf).With("component", "test")

	logger.InfoContext(context.Background(), "hello", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("failed to parse log line: %v", err)
	}
	if rec["component"] != "test" {
		t.Errorf("component attr lost through WithAttrs: %v", rec["component"])
	}
	if rec["k"] != "v" {
		t.Errorf("inline attr lost: %v", rec["k"])
	}
}
