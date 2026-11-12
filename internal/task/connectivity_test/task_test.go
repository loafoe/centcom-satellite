package connectivity_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/loafoe/centcom-satellite/internal/clusteraddr"
)

func TestTask_Name(t *testing.T) {
	task := New()
	assert.Equal(t, "connectivity_test", task.Name())
}

// newLoopbackTestTask returns a Task whose guard allows loopback, so tests
// can exercise the success paths against local httptest/TCP listeners.
// The production guard (cluster-internal only) is covered separately in
// TestTask_Execute_GuardBlocksNonClusterTargets.
func newLoopbackTestTask() *Task {
	dialer := clusteraddr.GuardDialer(func(ip net.IP) bool {
		return ip.IsLoopback() || clusteraddr.IsClusterIP(ip)
	})
	return &Task{
		dialer: dialer.DialContext,
		httpClient: func(timeout time.Duration) *http.Client {
			d := clusteraddr.GuardDialer(func(ip net.IP) bool {
				return ip.IsLoopback() || clusteraddr.IsClusterIP(ip)
			})
			d.Timeout = timeout
			return &http.Client{
				Timeout:   timeout,
				Transport: &http.Transport{DialContext: d.DialContext},
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		},
	}
}

func TestTask_Execute_TCPSuccess(t *testing.T) {
	// Start a test TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	task := newLoopbackTestTask()
	payload, _ := json.Marshal(Payload{Target: listener.Addr().String(), Protocol: "tcp"})

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	assert.True(t, result.Success)

	details, ok := result.Details.(*ConnectivityResult)
	require.True(t, ok)
	assert.True(t, details.Success)
	assert.Equal(t, "tcp", details.Protocol)
	assert.Empty(t, details.Error)
	assert.Greater(t, details.DurationMs, int64(-1))
}

func TestTask_Execute_TCPFailure(t *testing.T) {
	task := newLoopbackTestTask()
	// Use a port that's unlikely to be listening
	payload, _ := json.Marshal(Payload{Target: "127.0.0.1:59999", Protocol: "tcp", TimeoutMs: 1000})

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	assert.True(t, result.Success) // Task succeeds, but connectivity failed

	details, ok := result.Details.(*ConnectivityResult)
	require.True(t, ok)
	assert.False(t, details.Success)
	assert.NotEmpty(t, details.Error)
}

func TestTask_Execute_HTTPSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := newLoopbackTestTask()
	payload, _ := json.Marshal(Payload{Target: server.URL})

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*ConnectivityResult)
	require.True(t, ok)
	assert.True(t, details.Success)
	assert.Equal(t, "http", details.Protocol)
	assert.Equal(t, 200, details.StatusCode)
}

func TestTask_Execute_HTTPSWithTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Use the test server's client which trusts its certificate, but keep
	// the production redirect policy so its behavior stays covered.
	task := &Task{
		dialer: (&net.Dialer{}).DialContext,
		httpClient: func(timeout time.Duration) *http.Client {
			client := server.Client()
			client.Timeout = timeout
			client.CheckRedirect = func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}
			return client
		},
	}

	payload, _ := json.Marshal(Payload{Target: server.URL})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*ConnectivityResult)
	require.True(t, ok)
	assert.True(t, details.Success)
	assert.Equal(t, 200, details.StatusCode)
	assert.NotEmpty(t, details.TLSVersion)
}

func TestTask_Execute_MissingTarget(t *testing.T) {
	task := New()
	payload, _ := json.Marshal(Payload{})

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "target is required")
}

func TestTask_Execute_ProtocolDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := newLoopbackTestTask()

	// URL should auto-detect HTTP
	payload, _ := json.Marshal(Payload{Target: server.URL})
	result, _ := task.Execute(context.Background(), payload)
	details := result.Details.(*ConnectivityResult)
	assert.Equal(t, "http", details.Protocol)
}

func TestTask_Execute_TimeoutEnforced(t *testing.T) {
	task := &Task{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				return nil, errors.New("should not reach here")
			}
		},
		httpClient: New().httpClient,
	}

	payload, _ := json.Marshal(Payload{Target: "10.255.255.1:80", Protocol: "tcp", TimeoutMs: 100})
	start := time.Now()
	result, _ := task.Execute(context.Background(), payload)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond)
	details := result.Details.(*ConnectivityResult)
	assert.False(t, details.Success)
}

// TestTask_Execute_GuardBlocksNonClusterTargets is the security contract
// of this task (security review F-1): the production constructor's dialer
// must refuse to connect to anything outside the cluster-internal ranges -
// in particular the cloud metadata service, loopback, and public internet
// addresses. A refused target is reported as a connectivity failure, not
// a task error.
func TestTask_Execute_GuardBlocksNonClusterTargets(t *testing.T) {
	blocked := []string{
		"169.254.169.254:80",  // cloud metadata service
		"169.254.170.2:80",    // ECS credentials endpoint
		"127.0.0.1:80",        // loopback
		"8.8.8.8:443",         // public internet
		"example.com:443",     // public DNS name
	}
	task := New()

	for _, target := range blocked {
		t.Run(target, func(t *testing.T) {
			payload, _ := json.Marshal(Payload{Target: target, Protocol: "tcp", TimeoutMs: 500})
			result, err := task.Execute(context.Background(), payload)
			require.NoError(t, err)

			details, ok := result.Details.(*ConnectivityResult)
			require.True(t, ok)
			assert.False(t, details.Success, "guard must refuse %s", target)
			assert.Contains(t, details.Error, "blocked")
		})
	}
}

// TestTask_Execute_HTTPGuardBlocksNonClusterURL checks the HTTP path
// specifically: a URL whose host resolves/points outside the cluster
// ranges must be refused by the guarded transport, and the connection
// must never succeed against it.
func TestTask_Execute_HTTPGuardBlocksNonClusterURL(t *testing.T) {
	task := New()
	payload, _ := json.Marshal(Payload{Target: "http://169.254.169.254/latest/meta-data/", TimeoutMs: 500})

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*ConnectivityResult)
	require.True(t, ok)
	assert.False(t, details.Success)
	assert.Contains(t, details.Error, "blocked")
	assert.NotContains(t, details.Error, "iam") // never reached the metadata service
}

// TestTask_Execute_HTTPRedirectNotFollowed checks that a 3xx from an
// in-cluster endpoint is returned to the caller instead of being chased to
// a (potentially non-cluster) redirect target.
func TestTask_Execute_HTTPRedirectNotFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://169.254.169.254/latest/meta-data/")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := newLoopbackTestTask()
	payload, _ := json.Marshal(Payload{Target: server.URL + "/redirect"})

	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	details, ok := result.Details.(*ConnectivityResult)
	require.True(t, ok)
	assert.True(t, details.Success)
	assert.Equal(t, http.StatusFound, details.StatusCode, "the 302 must be surfaced, not followed")
}
