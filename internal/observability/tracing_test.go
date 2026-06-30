package observability

import (
	"context"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func TestSetupTracingInstallsPropagatorWhenDisabled(t *testing.T) {
	// With no endpoint, export is disabled but the global propagator must
	// still be installed so trace context flows end to end.
	shutdown, err := SetupTracing(context.Background(), "centcom-satellite", "test", "")
	if err != nil {
		t.Fatalf("SetupTracing returned error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	prop := otel.GetTextMapPropagator()
	fields := prop.Fields()
	hasTraceparent := false
	for _, f := range fields {
		if f == "traceparent" {
			hasTraceparent = true
		}
	}
	if !hasTraceparent {
		t.Errorf("global propagator missing traceparent field, got %v", fields)
	}
}

func TestPropagatorRoundTripsTraceContext(t *testing.T) {
	// Simulate pico-mcp injecting trace context, then centcom-satellite extracting it.
	traceID, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	spanID, _ := trace.SpanIDFromHex("2222222222222222")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	header := http.Header{}
	Propagator.Inject(ctx, propagation.HeaderCarrier(header))

	if header.Get("traceparent") == "" {
		t.Fatal("traceparent not injected")
	}

	extracted := Propagator.Extract(context.Background(), propagation.HeaderCarrier(header))
	got := trace.SpanContextFromContext(extracted)
	if got.TraceID() != traceID {
		t.Errorf("extracted TraceID = %v, want %v", got.TraceID(), traceID)
	}
	if got.SpanID() != spanID {
		t.Errorf("extracted SpanID = %v, want %v", got.SpanID(), spanID)
	}
}
