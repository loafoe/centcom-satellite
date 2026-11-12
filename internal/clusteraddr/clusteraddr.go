// Package clusteraddr provides the shared "is this address cluster-internal?"
// allowlist and a dialer guard used by network-touching tasks
// (http_request, connectivity_test) to prevent server-side request
// forgery: a caller must never be able to make the satellite connect to
// the cloud metadata service, loopback, link-local, or public internet
// addresses through a task.
//
// It lives here rather than inside any one task package so that every
// network-touching task enforces the exact same rule, from the exact same
// code, and a future task can't quietly grow a weaker variant.
package clusteraddr

import (
	"fmt"
	"net"
	"syscall"
)

// clusterCIDRs are the private ranges cluster pods and services live in:
// RFC1918 plus RFC 6598 shared address space (EKS secondary pod CIDRs).
// Loopback, link-local (incl. the 169.254.169.254 metadata service) and
// public addresses are never cluster-internal.
var clusterCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

// IsClusterIP reports whether ip falls inside one of the cluster-internal
// CIDRs. IPv4-mapped IPv6 addresses are handled by net.IP's Contains.
func IsClusterIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range clusterCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Cannot happen: the list above is fixed and valid.
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ErrBlockedAddress is the sentinel returned by the guarded dialer's
// Control hook (and thus surfaced inside a dial error) when the address
// about to be connected to is not cluster-internal.
var ErrBlockedAddress = fmt.Errorf("connection to a non-cluster address blocked")

// GuardDialer returns a net.Dialer whose Control hook rejects any connect
// to a non-cluster-internal IP, checked after DNS resolution - so a name
// that resolved to a cluster IP during pre-flight validation and to
// something else at connect time (DNS rebinding) is still refused.
// allow lets tests substitute a narrower/wider predicate; nil means
// IsClusterIP.
func GuardDialer(allow func(net.IP) bool) *net.Dialer {
	if allow == nil {
		allow = IsClusterIP
	}
	return &net.Dialer{
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
			}
			ip := net.ParseIP(host)
			if ip == nil || !allow(ip) {
				return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
			}
			return nil
		},
	}
}
