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
)

func TestTask_Name(t *testing.T) {
	task := New()
	assert.Equal(t, "connectivity_test", task.Name())
}

func TestTask_Execute_TCPSuccess(t *testing.T) {
	// Start a test TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	task := New()
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
	task := New()
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

	task := New()
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

	// Use the test server's client which trusts its certificate
	task := &Task{
		dialer: (&net.Dialer{}).DialContext,
		httpClient: func(timeout time.Duration) *http.Client {
			client := server.Client()
			client.Timeout = timeout
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

	task := New()

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
