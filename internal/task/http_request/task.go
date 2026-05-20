// Package http_request provides HTTP request functionality for cluster-internal services.
package http_request

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "http_request"

const (
	defaultTimeoutMs = 5000
	maxTimeoutMs     = 30000
	maxBodySize      = 64 * 1024 // 64KB
)

type Payload struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	TimeoutMs   int               `json:"timeout_ms,omitempty"`
}

type HTTPResult struct {
	StatusCode    int               `json:"status_code"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
	DurationMs    int64             `json:"duration_ms"`
}

type Task struct {
	httpClient func(timeout time.Duration) *http.Client
	resolver   func(ctx context.Context, host string) ([]net.IP, error)
}

func New() *Task {
	return &Task{
		httpClient: func(timeout time.Duration) *http.Client {
			return &http.Client{Timeout: timeout}
		},
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			return addrs, err
		},
	}
}

func (t *Task) Name() string {
	return TaskName
}

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
	}

	if payload.Method == "" {
		return task.NewErrorResult("method is required"), nil
	}
	if payload.URL == "" {
		return task.NewErrorResult("url is required"), nil
	}

	method := strings.ToUpper(payload.Method)
	if method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" {
		return task.NewErrorResult("method must be GET, POST, PUT, or DELETE"), nil
	}

	parsedURL, err := url.Parse(payload.URL)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("invalid URL: %v", err)), nil
	}

	if parsedURL.Scheme != "http" {
		return task.NewErrorResult("only http:// URLs are allowed (cluster-internal)"), nil
	}

	if err := t.validateClusterInternal(ctx, parsedURL.Hostname()); err != nil {
		return task.NewErrorResult(fmt.Sprintf("URL not cluster-internal: %v", err)), nil
	}

	timeoutMs := payload.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}
	if timeoutMs > maxTimeoutMs {
		timeoutMs = maxTimeoutMs
	}

	result, err := t.doRequest(ctx, method, payload, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return task.NewErrorResult(fmt.Sprintf("request failed: %v", err)), nil
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("HTTP %d %s", result.StatusCode, result.Status),
		result,
	), nil
}

func (t *Task) validateClusterInternal(ctx context.Context, host string) error {
	if isKubernetesDNS(host) {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	ips, err := t.resolver(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %v", err)
	}

	for _, ip := range ips {
		if !isClusterIP(ip) {
			return fmt.Errorf("host resolves to non-cluster IP: %s", ip)
		}
	}
	return nil
}

func isKubernetesDNS(host string) bool {
	if strings.HasSuffix(host, ".svc.cluster.local") ||
		strings.HasSuffix(host, ".pod.cluster.local") ||
		strings.HasSuffix(host, ".svc") {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) == 2 {
		return true // name.namespace format
	}
	return false
}

func isClusterIP(ip net.IP) bool {
	// Common cluster CIDRs - pod and service ranges
	clusterCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range clusterCIDRs {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *Task) doRequest(ctx context.Context, method string, payload Payload, timeout time.Duration) (*HTTPResult, error) {
	var bodyReader io.Reader
	if payload.Body != "" {
		bodyReader = strings.NewReader(payload.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, payload.URL, bodyReader)
	if err != nil {
		return nil, err
	}

	contentType := payload.ContentType
	if contentType == "" && payload.Body != "" {
		contentType = "application/x-www-form-urlencoded"
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	for k, v := range payload.Headers {
		req.Header.Set(k, v)
	}

	client := t.httpClient(timeout)
	start := time.Now()
	resp, err := client.Do(req)
	durationMs := time.Since(start).Milliseconds()

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	truncated := len(body) > maxBodySize
	if truncated {
		body = body[:maxBodySize]
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &HTTPResult{
		StatusCode:    resp.StatusCode,
		Status:        http.StatusText(resp.StatusCode),
		Headers:       headers,
		Body:          string(body),
		BodyTruncated: truncated,
		DurationMs:    durationMs,
	}, nil
}
