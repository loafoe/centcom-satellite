package workload_exposure

import "testing"

func TestLBVerdict(t *testing.T) {
	scheme := "service.beta.kubernetes.io/aws-load-balancer-scheme"
	for _, c := range []struct {
		name  string
		ann   map[string]string
		class string
		addrs []string
		want  string
	}{
		{"AWS internet-facing (fleet platform gateway)", map[string]string{scheme: "internet-facing"}, "", []string{"x.elb.us-east-1.amazonaws.com"}, Internet},
		{"AWS internal", map[string]string{scheme: "internal"}, "", []string{"internal-x.elb.us-east-1.amazonaws.com"}, Internal},
		{"internet-facing but not provisioned", map[string]string{scheme: "internet-facing"}, "", nil, Unknown},
		{"AWS LBC default is internal", nil, "service.k8s.aws/nlb", []string{"x.elb.amazonaws.com"}, Internal},
		{"legacy AWS internal annotation", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"}, "", []string{"10.0.0.5"}, Internal},
		{"Azure internal", map[string]string{"service.beta.kubernetes.io/azure-load-balancer-internal": "true"}, "", []string{"10.1.0.4"}, Internal},
		{"GKE internal", map[string]string{"networking.gke.io/load-balancer-type": "Internal"}, "", []string{"10.2.0.9"}, Internal},
		{"plain public IP", nil, "", []string{"203.0.113.10"}, Internet},
		{"private IP only (e.g. MetalLB on a LAN)", nil, "", []string{"192.168.1.240"}, Internal},
		{"CGNAT / tailnet address", nil, "", []string{"100.101.102.103"}, Internal},
		{"AWS internal- DNS name", nil, "", []string{"internal-foo-123.eu-west-1.elb.amazonaws.com"}, Internal},
		{"hostname without markers", nil, "", []string{"lb.example.com"}, Internet},
		{"no address", nil, "", nil, Unknown},
	} {
		if got, why := lbVerdict(c.ann, c.class, c.addrs); got != c.want || why == "" {
			t.Errorf("%s: got %q (%s), want %q", c.name, got, why, c.want)
		}
	}
}

func TestWorseAndOpenToAll(t *testing.T) {
	if worse(Internal, Internet) != Internet || worse(Internet, Unknown) != Internet || worse(Internal, Unknown) != Unknown {
		t.Fatal("worse must rank internet > unknown > internal")
	}
	if !openToAll(nil) || !openToAll([]string{"0.0.0.0/0"}) || openToAll([]string{"198.51.100.0/24"}) {
		t.Fatal("openToAll")
	}
}
