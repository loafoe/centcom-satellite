package observability

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all application metrics.
type Metrics struct {
	// HTTP metrics
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	// Task metrics
	TasksTotal    *prometheus.CounterVec
	TasksDuration *prometheus.HistogramVec
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
				Name: "pico_agent_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pico_agent_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		TasksTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pico_agent_tasks_total",
				Help: "Total number of tasks executed",
			},
			[]string{"type", "status"},
		),
		TasksDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pico_agent_task_duration_seconds",
				Help:    "Task execution duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"type"},
		),
	}

	reg.MustRegister(m.HTTPRequestsTotal, m.HTTPRequestDuration, m.TasksTotal, m.TasksDuration)

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
