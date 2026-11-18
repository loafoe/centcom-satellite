package workload_exposure

import (
	"net"
	"strings"
)

// Exposure values.
const (
	Internet = "internet" // reachable from the Internet
	Internal = "internal" // has a load balancer / address, but private
	Unknown  = "unknown"  // can't tell (e.g. load balancer not provisioned yet)
)

// lbVerdict classifies one load balancer from what the Kubernetes API shows:
// its annotations (the Service's, or a Gateway's infrastructure annotations
// that the controller copies onto it), load balancer class and the
// addresses in its status. No cloud API is used.
func lbVerdict(annotations map[string]string, lbClass string, addresses []string) (exposure, reason string) {
	a := func(k string) string { return strings.ToLower(strings.TrimSpace(annotations[k])) }
	switch a("service.beta.kubernetes.io/aws-load-balancer-scheme") {
	case "internal":
		return Internal, "AWS load balancer scheme: internal"
	case "internet-facing":
		if len(addresses) == 0 {
			return Unknown, "AWS load balancer scheme internet-facing, but no address yet"
		}
		return Internet, "AWS load balancer scheme: internet-facing"
	}
	if v := a("service.beta.kubernetes.io/aws-load-balancer-internal"); v == "true" || v == "0.0.0.0/0" {
		return Internal, "AWS internal load balancer annotation"
	}
	if a("service.beta.kubernetes.io/azure-load-balancer-internal") == "true" {
		return Internal, "Azure internal load balancer annotation"
	}
	if a("networking.gke.io/load-balancer-type") == "internal" || a("cloud.google.com/load-balancer-type") == "internal" {
		return Internal, "GKE internal load balancer annotation"
	}
	// The AWS Load Balancer Controller provisions an internal NLB unless
	// told otherwise (unlike the legacy in-tree provider).
	if lbClass == "service.k8s.aws/nlb" || a("service.beta.kubernetes.io/aws-load-balancer-type") == "external" || a("service.beta.kubernetes.io/aws-load-balancer-type") == "nlb-ip" {
		return Internal, "AWS Load Balancer Controller without a scheme annotation (defaults to internal)"
	}
	return addressVerdict(addresses)
}

// addressVerdict classifies by the addresses alone.
func addressVerdict(addresses []string) (exposure, reason string) {
	if len(addresses) == 0 {
		return Unknown, "no load balancer address yet"
	}
	for _, addr := range addresses {
		if ip := net.ParseIP(addr); ip != nil {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || inCGNAT(ip) {
				continue
			}
			return Internet, "public IP address " + addr
		}
		// AWS names internal ELBs internal-<name>-<id>.<region>.elb.amazonaws.com.
		if strings.HasPrefix(strings.ToLower(addr), "internal-") && strings.Contains(addr, ".elb.") {
			continue
		}
		return Internet, "load balancer address " + addr
	}
	return Internal, "private address only (" + strings.Join(addresses, ", ") + ")"
}

var cgnat = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

func inCGNAT(ip net.IP) bool { return cgnat.Contains(ip) }

// openToAll reports whether source ranges allow everyone (or are unset).
func openToAll(ranges []string) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, r := range ranges {
		if r == "0.0.0.0/0" || r == "::/0" {
			return true
		}
	}
	return false
}

// worse picks the more exposed verdict (internet > unknown > internal).
func worse(a, b string) string {
	rank := map[string]int{Internet: 3, Unknown: 2, Internal: 1}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
