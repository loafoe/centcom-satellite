package clusteraddr

import (
	"net"
	"testing"
	"time"
)

func TestIsClusterIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"169.254.169.254", false}, // cloud metadata service
		{"169.254.170.2", false},   // ECS credentials endpoint
		{"127.0.0.1", false},
		{"100.128.0.1", false},
		{"::ffff:10.0.0.1", true},
		{"::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := IsClusterIP(net.ParseIP(tt.ip)); got != tt.want {
				t.Errorf("IsClusterIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsClusterIPNil(t *testing.T) {
	if IsClusterIP(nil) {
		t.Error("IsClusterIP(nil) must be false")
	}
}

// TestGuardDialerBlocksNonCluster is the shared SSRF contract: the dialer
// used by http_request and connectivity_test must refuse to connect
// outside the cluster ranges, including the metadata service and loopback.
func TestGuardDialerBlocksNonCluster(t *testing.T) {
	d := GuardDialer(nil)
	for _, addr := range []string{"169.254.169.254:80", "127.0.0.1:80", "8.8.8.8:443"} {
		conn, err := d.Dial("tcp", addr)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Errorf("dial to %s must be blocked", addr)
			continue
		}
		if !isBlocked(err) {
			t.Errorf("dial to %s: want ErrBlockedAddress, got %v", addr, err)
		}
	}
}

func TestGuardDialerAllowsClusterIP(t *testing.T) {
	// A cluster-range address with no listener should fail with a
	// connection error (refused/timeout), NOT the guard's blocked error.
	// Short Timeout so the non-routable address doesn't stall the test.
	d := GuardDialer(nil)
	d.Timeout = 2 * time.Second
	_, err := d.Dial("tcp", "10.255.255.1:80")
	if err == nil {
		t.Error("expected an error (no listener), got nil")
	}
	if isBlocked(err) {
		t.Errorf("cluster-internal address must not be blocked by the guard, got %v", err)
	}
}

func isBlocked(err error) bool {
	for err != nil {
		if err == ErrBlockedAddress {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
