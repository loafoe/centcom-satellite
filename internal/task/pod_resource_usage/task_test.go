package pod_resource_usage

import "testing"

func TestMetricsPath(t *testing.T) {
	cases := []struct {
		namespace string
		want      string
	}{
		{namespace: "", want: "/apis/metrics.k8s.io/v1beta1/pods"},
		{namespace: "default", want: "/apis/metrics.k8s.io/v1beta1/namespaces/default/pods"},
		{namespace: "kube-system", want: "/apis/metrics.k8s.io/v1beta1/namespaces/kube-system/pods"},
	}
	for _, c := range cases {
		if got := metricsPath(c.namespace); got != c.want {
			t.Errorf("metricsPath(%q) = %q, want %q", c.namespace, got, c.want)
		}
	}
}
