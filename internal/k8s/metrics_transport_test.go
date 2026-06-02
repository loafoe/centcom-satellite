package k8s

import (
	"errors"
	"net/http"
	"testing"
)

func TestResourceFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/namespaces/default/pods", "pods"},
		{"/api/v1/namespaces/default/pods/my-pod", "pods"},
		{"/api/v1/namespaces/default/pods/my-pod/log", "pods/log"},
		{"/api/v1/namespaces/default/configmaps", "configmaps"},
		{"/api/v1/namespaces", "namespaces"},
		{"/api/v1/nodes", "nodes"},
		{"/api/v1/namespaces/default/persistentvolumeclaims/pvc-1", "persistentvolumeclaims"},
		{"/apis/apps/v1/namespaces/default/deployments", "deployments"},
		{"/apis/apps/v1/namespaces/default/deployments/web/scale", "deployments"}, // scale subresource not tracked separately; falls back to base resource
		{"/apis/karpenter.sh/v1/nodeclaims", "nodeclaims"},
		{"/apis/networking.k8s.io/v1/namespaces/ns/ingresses", "ingresses"},
		{"/healthz", "other"},
		{"/", "other"},
		{"", "other"},
		{"/api/v1/namespaces/default/somethingweird", "other"},
	}

	for _, tc := range cases {
		if got := resourceFromPath(tc.path); got != tc.want {
			t.Errorf("resourceFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// recorderStub captures the most recent RecordK8sRequest call.
type recorderStub struct {
	verb, resource, statusClass string
	called                      bool
}

func (r *recorderStub) RecordK8sRequest(verb, resource, statusClass string, _ float64) {
	r.verb, r.resource, r.statusClass = verb, resource, statusClass
	r.called = true
}

// fakeRT returns a fixed response/error.
type fakeRT struct {
	resp *http.Response
	err  error
}

func (f *fakeRT) RoundTrip(*http.Request) (*http.Response, error) {
	return f.resp, f.err
}

func TestMetricsRoundTripper_RecordsStatusClass(t *testing.T) {
	rec := &recorderStub{}
	rt := wrapTransport(rec)(&fakeRT{resp: &http.Response{StatusCode: 200}})

	req, _ := http.NewRequest(http.MethodGet, "https://k8s/api/v1/namespaces/default/pods", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !rec.called {
		t.Fatal("recorder was not called")
	}
	if rec.verb != "get" || rec.resource != "pods" || rec.statusClass != "2xx" {
		t.Errorf("got verb=%q resource=%q statusClass=%q", rec.verb, rec.resource, rec.statusClass)
	}
}

func TestMetricsRoundTripper_RecordsTransportError(t *testing.T) {
	rec := &recorderStub{}
	rt := wrapTransport(rec)(&fakeRT{err: errors.New("dial failed")})

	req, _ := http.NewRequest(http.MethodDelete, "https://k8s/apis/karpenter.sh/v1/nodeclaims/nc-1", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("expected error to propagate")
	}

	if rec.verb != "delete" || rec.resource != "nodeclaims" || rec.statusClass != "error" {
		t.Errorf("got verb=%q resource=%q statusClass=%q", rec.verb, rec.resource, rec.statusClass)
	}
}
