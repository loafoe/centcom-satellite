package observability

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
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
var Tracer trace.Tracer = noop.NewTracerProvider().Tracer("pico-agent")

// TracerShutdown is a function to shut down the tracer provider.
type TracerShutdown func(context.Context) error

// SetupTracing initializes OpenTelemetry tracing.
// If endpoint is empty, tracing is disabled but a no-op tracer is still available.
func SetupTracing(ctx context.Context, serviceName, version, endpoint string) (TracerShutdown, error) {
	// Always set up a tracer so code can use it without checking
	Tracer = otel.Tracer(serviceName)

	if endpoint == "" {
		slog.Info("tracing disabled, no OTEL endpoint configured")
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

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // TODO: make configurable
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	Tracer = tp.Tracer(serviceName)

	slog.Info("tracing enabled", "endpoint", endpoint)

	return tp.Shutdown, nil
}

// StartSpan starts a new span with the given name.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return Tracer.Start(ctx, name)
}
