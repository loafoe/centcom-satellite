// Package connectivity_test provides TCP/HTTP connectivity testing functionality.
package connectivity_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "connectivity_test"

const (
	defaultTimeoutMs = 5000
	maxTimeoutMs     = 30000
)

// Payload for connectivity_test task.
type Payload struct {
	Target    string `json:"target"`
	Protocol  string `json:"protocol,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

// ConnectivityResult contains connectivity test results.
type ConnectivityResult struct {
	Target     string `json:"target"`
	Protocol   string `json:"protocol"`
	Success    bool   `json:"success"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
}

// Task handles connectivity testing.
type Task struct {
	dialer     func(ctx context.Context, network, address string) (net.Conn, error)
	httpClient func(timeout time.Duration) *http.Client
}

// New creates a new connectivity test task.
func New() *Task {
	return &Task{
		dialer: (&net.Dialer{}).DialContext,
		httpClient: func(timeout time.Duration) *http.Client {
			return &http.Client{
				Timeout: timeout,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
				},
			}
		},
	}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs connectivity test.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	if payload.Target == "" {
		return task.NewErrorResult("target is required"), nil
	}

	// Determine protocol
	protocol := strings.ToLower(payload.Protocol)
	if protocol == "" {
		if strings.HasPrefix(payload.Target, "http://") || strings.HasPrefix(payload.Target, "https://") {
			protocol = "http"
		} else {
			protocol = "tcp"
		}
	}

	// Set timeout
	timeoutMs := payload.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}
	if timeoutMs > maxTimeoutMs {
		timeoutMs = maxTimeoutMs
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	var result *ConnectivityResult
	if protocol == "http" {
		result = t.testHTTP(ctx, payload.Target, timeout)
	} else {
		result = t.testTCP(ctx, payload.Target, timeout)
	}

	msg := fmt.Sprintf("Connectivity test to %s: ", result.Target)
	if result.Success {
		msg += "success"
	} else {
		msg += "failed"
	}

	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) testTCP(ctx context.Context, target string, timeout time.Duration) *ConnectivityResult {
	result := &ConnectivityResult{
		Target:   target,
		Protocol: "tcp",
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	conn, err := t.dialer(ctx, "tcp", target)
	result.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer func() { _ = conn.Close() }()

	result.Success = true
	return result
}

func (t *Task) testHTTP(ctx context.Context, target string, timeout time.Duration) *ConnectivityResult {
	result := &ConnectivityResult{
		Target:   target,
		Protocol: "http",
	}

	// Ensure target is a valid URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		return result
	}
	result.Target = parsedURL.String()

	client := t.httpClient(timeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, result.Target, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	start := time.Now()
	resp, err := client.Do(req)
	result.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	result.Success = true
	result.StatusCode = resp.StatusCode

	if resp.TLS != nil {
		result.TLSVersion = tlsVersionString(resp.TLS.Version)
	}

	return result
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
