package http_request

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateClusterInternal(t *testing.T) {
	task := New()

	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"k8s svc.cluster.local", "my-svc.my-ns.svc.cluster.local", false},
		{"k8s name.namespace", "my-svc.my-ns", false},
		{"k8s .svc suffix", "my-svc.my-ns.svc", false},
		{"k8s pod.cluster.local", "10-0-0-1.my-ns.pod.cluster.local", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := task.validateClusterInternal(context.Background(), tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateClusterInternal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsKubernetesDNS(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"my-svc.my-ns.svc.cluster.local", true},
		{"my-svc.my-ns.svc", true},
		{"my-svc.my-ns", true},
		{"10-0-0-1.my-ns.pod.cluster.local", true},
		{"my-svc", false},
		{"example.com", true}, // Two parts treated as name.namespace
		{"my-svc.my-ns.other.domain", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isKubernetesDNS(tt.host); got != tt.want {
				t.Errorf("isKubernetesDNS(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

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
		{"8.8.8.8", false},
		{"1.2.3.4", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := isClusterIP(ip); got != tt.want {
				t.Errorf("isClusterIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestExecuteGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	task := &Task{
		httpClient: func(timeout time.Duration) *http.Client {
			return server.Client()
		},
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}

	payload, _ := json.Marshal(Payload{Method: "GET", URL: server.URL})
	result, err := task.Execute(context.Background(), payload)

	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !result.Success {
		t.Errorf("Execute() success = false, want true: %s", result.Error)
	}
}

func TestExecutePOST(t *testing.T) {
	var receivedBody string
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body := make([]byte, 1024)
		n, _ := r.Body.Read(body)
		receivedBody = string(body[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := &Task{
		httpClient: func(timeout time.Duration) *http.Client {
			return server.Client()
		},
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}

	payload, _ := json.Marshal(Payload{
		Method: "POST",
		URL:    server.URL,
		Body:   "forget=member-1",
	})
	result, err := task.Execute(context.Background(), payload)

	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !result.Success {
		t.Errorf("Execute() success = false: %s", result.Error)
	}
	if receivedBody != "forget=member-1" {
		t.Errorf("received body = %q, want %q", receivedBody, "forget=member-1")
	}
	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q, want application/x-www-form-urlencoded", receivedContentType)
	}
}

func TestExecuteWithCustomHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := &Task{
		httpClient: func(timeout time.Duration) *http.Client {
			return server.Client()
		},
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}

	payload, _ := json.Marshal(Payload{
		Method:  "GET",
		URL:     server.URL,
		Headers: map[string]string{"Authorization": "Bearer token123"},
	})
	result, _ := task.Execute(context.Background(), payload)

	if !result.Success {
		t.Errorf("Execute() success = false: %s", result.Error)
	}
	if receivedAuth != "Bearer token123" {
		t.Errorf("Authorization header = %q, want %q", receivedAuth, "Bearer token123")
	}
}

func TestExecuteRejectsHTTPS(t *testing.T) {
	task := New()
	payload, _ := json.Marshal(Payload{Method: "GET", URL: "https://example.com"})
	result, _ := task.Execute(context.Background(), payload)

	if result.Success {
		t.Error("Expected failure for https URL")
	}
	if result.Error == "" {
		t.Error("Expected error message")
	}
}

func TestExecuteRejectsInvalidMethod(t *testing.T) {
	task := New()
	payload, _ := json.Marshal(Payload{Method: "PATCH", URL: "http://svc.ns:8080"})
	result, _ := task.Execute(context.Background(), payload)

	if result.Success {
		t.Error("Expected failure for PATCH method")
	}
}

func TestExecuteRequiresMethod(t *testing.T) {
	task := New()
	payload, _ := json.Marshal(Payload{URL: "http://svc.ns:8080"})
	result, _ := task.Execute(context.Background(), payload)

	if result.Success {
		t.Error("Expected failure when method missing")
	}
}

func TestExecuteRequiresURL(t *testing.T) {
	task := New()
	payload, _ := json.Marshal(Payload{Method: "GET"})
	result, _ := task.Execute(context.Background(), payload)

	if result.Success {
		t.Error("Expected failure when URL missing")
	}
}
