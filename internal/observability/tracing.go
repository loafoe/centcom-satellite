package observability

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Tracer is the global tracer for the application.
// It's initialized to a no-op tracer by default.
var Tracer trace.Tracer = noop.NewTracerProvider().Tracer("centcom-satellite")

// Propagator carries W3C trace context (traceparent/tracestate) and baggage
// across service boundaries. pico-mcp injects these headers when it calls us;
// we extract them on inbound requests and re-inject them on outbound calls
// (e.g. to the Kubernetes API) so a single trace spans the whole chain.
//
// It is configured unconditionally — even when no OTLP exporter is set — so
// that trace context propagation always works and downstream collectors can
// stitch traces together regardless of whether this process exports spans.
var Propagator propagation.TextMapPropagator = propagation.NewCompositeTextMapPropagator(
	propagation.TraceContext{},
	propagation.Baggage{},
)

// TracerShutdown is a function to shut down the tracer provider.
type TracerShutdown func(context.Context) error

// SetupTracing initializes OpenTelemetry tracing.
// If endpoint is empty, span export is disabled but a no-op tracer and the
// global propagator remain available so context still flows end to end.
func SetupTracing(ctx context.Context, serviceName, version, endpoint string) (TracerShutdown, error) {
	// Always install the global propagator so inbound extraction and outbound
	// injection work even when this process does not export spans itself.
	otel.SetTextMapPropagator(Propagator)

	// Always set up a tracer so code can use it without checking.
	Tracer = otel.Tracer(serviceName)

	if endpoint == "" {
		slog.Info("tracing disabled, no OTEL endpoint configured (trace context still propagated)")
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return nil, err
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	// Honour the standard OTEL_EXPORTER_OTLP_INSECURE toggle. Default to
	// insecure to preserve existing behaviour for plaintext collectors.
	if otlpInsecure() {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)

	otel.SetTracerProvider(tp)

	Tracer = tp.Tracer(serviceName)

	slog.Info("tracing enabled", "endpoint", endpoint, "insecure", otlpInsecure())

	return tp.Shutdown, nil
}

// otlpInsecure reports whether the OTLP exporter should use plaintext.
// Defaults to true (insecure) when unset for backward compatibility with
// in-cluster collectors reached over plain HTTP.
func otlpInsecure() bool {
	for _, key := range []string{"OTEL_EXPORTER_OTLP_TRACES_INSECURE", "OTEL_EXPORTER_OTLP_INSECURE"} {
		if v := os.Getenv(key); v != "" {
			switch strings.ToLower(v) {
			case "false", "0", "no", "off":
				return false
			default:
				return true
			}
		}
	}
	return true
}

// StartSpan starts a new span with the given name.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return Tracer.Start(ctx, name)
}

// RecordError marks the span associated with ctx as failed, recording the
// error as a span event and setting its status to Error. It is a no-op when
// the context carries no recording span (e.g. tracing disabled).
func RecordError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}
