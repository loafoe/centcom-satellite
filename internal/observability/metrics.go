package observability

import (
	"runtime"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all application metrics.
type Metrics struct {
	// HTTP metrics
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsInFlight prometheus.Gauge

	// Task metrics
	TasksTotal    *prometheus.CounterVec
	TasksDuration *prometheus.HistogramVec

	// Auth metrics
	AuthAttemptsTotal *prometheus.CounterVec

	// Kubernetes API client metrics
	K8sRequestsTotal   *prometheus.CounterVec
	K8sRequestDuration *prometheus.HistogramVec

	// Log streaming metrics
	LogStreamsActive  prometheus.Gauge
	LogStreamDuration prometheus.Histogram
	LogStreamLines    prometheus.Counter

	// Build info
	BuildInfo *prometheus.GaugeVec
}

var (
	defaultMetrics *Metrics
	metricsOnce    sync.Once
)

// NewMetrics creates and registers all application metrics.
// Metrics are only registered once with the default registry.
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		defaultMetrics = newMetricsWithRegistry(prometheus.DefaultRegisterer)
	})
	return defaultMetrics
}

// NewMetricsWithRegistry creates metrics with a custom registry (useful for testing).
func NewMetricsWithRegistry(reg prometheus.Registerer) *Metrics {
	return newMetricsWithRegistry(reg)
}

func newMetricsWithRegistry(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "centcom_satellite_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "centcom_satellite_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		HTTPRequestsInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "centcom_satellite_http_requests_in_flight",
				Help: "Number of HTTP requests currently being served",
			},
		),
		TasksTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "centcom_satellite_tasks_total",
				Help: "Total number of tasks executed",
			},
			[]string{"type", "status"},
		),
		TasksDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "centcom_satellite_task_duration_seconds",
				Help:    "Task execution duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"type"},
		),
		AuthAttemptsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "centcom_satellite_auth_attempts_total",
				Help: "Total number of authentication attempts by method and result",
			},
			[]string{"method", "result"},
		),
		K8sRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "centcom_satellite_k8s_requests_total",
				Help: "Total number of Kubernetes API requests issued by the agent",
			},
			[]string{"verb", "resource", "status_class"},
		),
		K8sRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "centcom_satellite_k8s_request_duration_seconds",
				Help:    "Kubernetes API request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"verb", "resource", "status_class"},
		),
		LogStreamsActive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "centcom_satellite_log_streams_active",
				Help: "Number of currently active log streams",
			},
		),
		LogStreamDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name: "centcom_satellite_log_stream_duration_seconds",
				Help: "Duration of completed log streams in seconds",
				// Streams are long-lived; use wide buckets from seconds to ~30 min.
				Buckets: []float64{1, 5, 15, 30, 60, 300, 900, 1800},
			},
		),
		LogStreamLines: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "centcom_satellite_log_stream_lines_total",
				Help: "Total number of log lines streamed to clients",
			},
		),
		BuildInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "centcom_satellite_build_info",
				Help: "Build information; constant 1 with version labels",
			},
			[]string{"version", "goversion"},
		),
	}

	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.HTTPRequestsInFlight,
		m.TasksTotal,
		m.TasksDuration,
		m.AuthAttemptsTotal,
		m.K8sRequestsTotal,
		m.K8sRequestDuration,
		m.LogStreamsActive,
		m.LogStreamDuration,
		m.LogStreamLines,
		m.BuildInfo,
	)

	return m
}

// RecordHTTPRequest records an HTTP request.
func (m *Metrics) RecordHTTPRequest(method, path, status string, duration float64) {
	m.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordTask records a task execution.
func (m *Metrics) RecordTask(taskType, status string, duration float64) {
	m.TasksTotal.WithLabelValues(taskType, status).Inc()
	m.TasksDuration.WithLabelValues(taskType).Observe(duration)
}

// RecordAuthAttempt records an authentication attempt by method and result.
func (m *Metrics) RecordAuthAttempt(method, result string) {
	m.AuthAttemptsTotal.WithLabelValues(method, result).Inc()
}

// RecordK8sRequest records a Kubernetes API request.
func (m *Metrics) RecordK8sRequest(verb, resource, statusClass string, duration float64) {
	m.K8sRequestsTotal.WithLabelValues(verb, resource, statusClass).Inc()
	m.K8sRequestDuration.WithLabelValues(verb, resource, statusClass).Observe(duration)
}

// SetBuildInfo sets the build_info gauge to 1 with the given version labels.
func (m *Metrics) SetBuildInfo(version string) {
	m.BuildInfo.WithLabelValues(version, runtime.Version()).Set(1)
}
