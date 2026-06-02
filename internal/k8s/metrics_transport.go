package k8s

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// K8sMetricsRecorder records Kubernetes API client request metrics.
// It is satisfied by *observability.Metrics; defined here to avoid an import cycle.
type K8sMetricsRecorder interface {
	RecordK8sRequest(verb, resource, statusClass string, duration float64)
}

// knownResources bounds the cardinality of the "resource" label. Anything not
// in this set is reported as "other".
var knownResources = map[string]struct{}{
	"pods":                   {},
	"services":               {},
	"endpoints":              {},
	"configmaps":             {},
	"secrets":                {},
	"namespaces":             {},
	"nodes":                  {},
	"events":                 {},
	"persistentvolumeclaims": {},
	"persistentvolumes":      {},
	"deployments":            {},
	"statefulsets":           {},
	"daemonsets":             {},
	"replicasets":            {},
	"ingresses":              {},
	"networkpolicies":        {},
	"nodeclaims":             {},
	"nodepools":              {},
	"applications":           {},
	"gateways":               {},
	"httproutes":             {},
	"routes":                 {},
	"verticalpodautoscalers": {},
	"pods/log":               {},
}

// metricsRoundTripper wraps an http.RoundTripper to record Prometheus metrics
// for every Kubernetes API request.
type metricsRoundTripper struct {
	next     http.RoundTripper
	recorder K8sMetricsRecorder
}

// wrapTransport returns a transport.WrapperFunc-compatible function that
// instruments the given RoundTripper.
func wrapTransport(recorder K8sMetricsRecorder) func(http.RoundTripper) http.RoundTripper {
	return func(rt http.RoundTripper) http.RoundTripper {
		return &metricsRoundTripper{next: rt, recorder: recorder}
	}
}

func (m *metricsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := m.next.RoundTrip(req)
	duration := time.Since(start).Seconds()

	verb := strings.ToLower(req.Method)
	resource := resourceFromPath(req.URL.Path)

	statusClass := "error"
	if err == nil && resp != nil {
		statusClass = strconv.Itoa(resp.StatusCode/100) + "xx"
	}

	m.recorder.RecordK8sRequest(verb, resource, statusClass, duration)
	return resp, err
}

// resourceFromPath extracts the Kubernetes resource type from an API request
// path and buckets unknown values to bound label cardinality.
//
// Paths look like:
//
//	/api/v1/namespaces/{ns}/pods
//	/api/v1/namespaces/{ns}/pods/{name}
//	/api/v1/namespaces/{ns}/pods/{name}/log
//	/apis/apps/v1/namespaces/{ns}/deployments
//	/apis/{group}/{version}/{resource}
func resourceFromPath(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")

	// Find where the version segment ends so the resource follows.
	// Core API: /api/v1/...   Grouped API: /apis/{group}/{version}/...
	var idx int
	switch {
	case len(segs) >= 2 && segs[0] == "api":
		idx = 2
	case len(segs) >= 3 && segs[0] == "apis":
		idx = 3
	default:
		return "other"
	}

	if idx >= len(segs) {
		return "other"
	}

	// Skip a leading namespaces/{ns} scoping segment to reach the real resource.
	resource := segs[idx]
	if resource == "namespaces" && idx+2 < len(segs) {
		resource = segs[idx+2]
	} else if resource == "namespaces" && idx+1 < len(segs) {
		// A request directly against the namespaces collection/object.
		resource = "namespaces"
	}

	// Detect subresources like pods/log by checking for a trailing known verb segment.
	// resource is at position p; if there is name + subresource, append it.
	p := indexOf(segs, resource, idx)
	if p >= 0 && p+2 < len(segs) {
		sub := segs[p+2]
		if sub == "log" || sub == "status" || sub == "scale" || sub == "eviction" {
			combined := resource + "/" + sub
			if _, ok := knownResources[combined]; ok {
				return combined
			}
		}
	}

	if _, ok := knownResources[resource]; ok {
		return resource
	}
	return "other"
}

func indexOf(segs []string, target string, from int) int {
	for i := from; i < len(segs); i++ {
		if segs[i] == target {
			return i
		}
	}
	return -1
}
