package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newTestMetrics(t *testing.T) (*Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	return NewMetricsWithRegistry(reg), reg
}

func TestRecordAuthAttempt(t *testing.T) {
	m, _ := newTestMetrics(t)
	m.RecordAuthAttempt("jwt", "success")
	m.RecordAuthAttempt("jwt", "success")
	m.RecordAuthAttempt("none", "unauthenticated")

	if got := testutil.ToFloat64(m.AuthAttemptsTotal.WithLabelValues("jwt", "success")); got != 2 {
		t.Errorf("jwt/success = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.AuthAttemptsTotal.WithLabelValues("none", "unauthenticated")); got != 1 {
		t.Errorf("none/unauthenticated = %v, want 1", got)
	}
}

func TestRecordK8sRequest(t *testing.T) {
	m, _ := newTestMetrics(t)
	m.RecordK8sRequest("get", "pods", "2xx", 0.01)

	if got := testutil.ToFloat64(m.K8sRequestsTotal.WithLabelValues("get", "pods", "2xx")); got != 1 {
		t.Errorf("k8s get/pods/2xx = %v, want 1", got)
	}
}

func TestSetBuildInfo(t *testing.T) {
	m, reg := newTestMetrics(t)
	m.SetBuildInfo("v1.2.3")

	// Assert the constant value 1 and that the version label is present;
	// goversion is runtime-dependent so it is not asserted exactly.
	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	found := false
	for _, fam := range mf {
		if fam.GetName() != "pico_agent_build_info" {
			continue
		}
		for _, metric := range fam.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "version" && lp.GetValue() == "v1.2.3" {
					found = true
				}
			}
			if metric.GetGauge().GetValue() != 1 {
				t.Errorf("build_info value = %v, want 1", metric.GetGauge().GetValue())
			}
		}
	}
	if !found {
		t.Error("build_info missing version=v1.2.3 label")
	}
}

func TestLogStreamMetrics(t *testing.T) {
	m, _ := newTestMetrics(t)
	m.LogStreamsActive.Inc()
	m.LogStreamLines.Add(5)
	m.LogStreamDuration.Observe(12.5)

	if got := testutil.ToFloat64(m.LogStreamsActive); got != 1 {
		t.Errorf("active streams = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.LogStreamLines); got != 5 {
		t.Errorf("stream lines = %v, want 5", got)
	}
}

func TestMetricsRegisterOnceWithDefaultRegistry(t *testing.T) {
	// NewMetrics must be idempotent against the default registry (panics on dup registration otherwise).
	a := NewMetrics()
	b := NewMetrics()
	if a != b {
		t.Error("NewMetrics should return the same singleton instance")
	}
}

func TestMetricFamiliesRegistered(t *testing.T) {
	m, reg := newTestMetrics(t)
	// Touch each family so it appears in Gather output.
	m.RecordHTTPRequest("GET", "/task", "OK", 0.1)
	m.HTTPRequestsInFlight.Inc()
	m.RecordTask("test", "success", 0.1)
	m.RecordAuthAttempt("dev", "success")
	m.RecordK8sRequest("get", "pods", "2xx", 0.1)
	m.LogStreamsActive.Inc()
	m.LogStreamLines.Inc()
	m.LogStreamDuration.Observe(1)
	m.SetBuildInfo("v0")

	want := []string{
		"pico_agent_http_requests_total",
		"pico_agent_http_request_duration_seconds",
		"pico_agent_http_requests_in_flight",
		"pico_agent_tasks_total",
		"pico_agent_task_duration_seconds",
		"pico_agent_auth_attempts_total",
		"pico_agent_k8s_requests_total",
		"pico_agent_k8s_request_duration_seconds",
		"pico_agent_log_streams_active",
		"pico_agent_log_stream_duration_seconds",
		"pico_agent_log_stream_lines_total",
		"pico_agent_build_info",
	}
	mf, _ := reg.Gather()
	have := map[string]bool{}
	for _, f := range mf {
		have[f.GetName()] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("expected metric family %q to be registered", n)
		}
	}
}
