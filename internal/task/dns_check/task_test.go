package dns_check

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockResolver struct {
	results map[string][]string
	err     error
}

func (m *mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	if addrs, ok := m.results[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("no such host")
}

func TestTask_Name(t *testing.T) {
	task := New()
	assert.Equal(t, "dns_check", task.Name())
}

func TestTask_Execute_Success(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]string{
			"my-service.default.svc.cluster.local": {"10.96.0.1", "10.96.0.2"},
		},
	}
	task := NewWithResolver(resolver)

	payload, _ := json.Marshal(Payload{Hostname: "my-service", Namespace: "default"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*DNSCheckResult)
	require.True(t, ok)
	assert.Equal(t, "my-service", details.Hostname)
	assert.Equal(t, "my-service.default.svc.cluster.local", details.Resolved)
	assert.Equal(t, []string{"10.96.0.1", "10.96.0.2"}, details.Addresses)
	assert.Empty(t, details.Error)
	assert.Greater(t, details.DurationMs, int64(-1))
}

func TestTask_Execute_FQDN(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]string{
			"google.com": {"142.250.80.46"},
		},
	}
	task := NewWithResolver(resolver)

	payload, _ := json.Marshal(Payload{Hostname: "google.com"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*DNSCheckResult)
	require.True(t, ok)
	assert.Equal(t, "google.com", details.Resolved)
	assert.Equal(t, []string{"142.250.80.46"}, details.Addresses)
}

func TestTask_Execute_NotFound(t *testing.T) {
	resolver := &mockResolver{
		results: map[string][]string{}, // empty - nothing resolves
	}
	task := NewWithResolver(resolver)

	payload, _ := json.Marshal(Payload{Hostname: "nonexistent", Namespace: "default"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	assert.True(t, result.Success) // Still success, but error in details

	details, ok := result.Details.(*DNSCheckResult)
	require.True(t, ok)
	assert.Empty(t, details.Resolved)
	assert.Empty(t, details.Addresses)
	assert.NotEmpty(t, details.Error)
}

func TestTask_Execute_MissingHostname(t *testing.T) {
	task := New()

	payload, _ := json.Marshal(Payload{})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "hostname is required")
}

func TestTask_BuildNamesToTry(t *testing.T) {
	task := New()

	// With namespace
	names := task.buildNamesToTry("my-svc", "prod")
	assert.Equal(t, []string{
		"my-svc.prod.svc.cluster.local",
		"my-svc.prod.svc",
		"my-svc.prod",
		"my-svc",
	}, names)

	// Without namespace
	names = task.buildNamesToTry("my-svc", "")
	assert.Equal(t, []string{"my-svc"}, names)

	// FQDN (contains dots)
	names = task.buildNamesToTry("my-svc.other-ns.svc.cluster.local", "default")
	assert.Equal(t, []string{"my-svc.other-ns.svc.cluster.local"}, names)
}
