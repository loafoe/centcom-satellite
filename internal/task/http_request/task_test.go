package http_request

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateClusterInternal(t *testing.T) {
	dns := map[string][]net.IP{
		"my-svc.my-ns":                   {net.ParseIP("10.43.0.5")},
		"my-svc.my-ns.svc.cluster.local": {net.ParseIP("10.43.0.5")},
		"pod.eks-secondary":              {net.ParseIP("100.64.3.4")},
		"example.com":                    {net.ParseIP("93.184.216.34")},
		// An ExternalName service is a *.svc.cluster.local name for an
		// outside host.
		"ext.my-ns.svc.cluster.local": {net.ParseIP("52.1.2.3")},
		"169.254.169.254":             {net.ParseIP("169.254.169.254")},
		"split.my-ns":                 {net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8")},
	}
	tk := &Task{resolver: func(ctx context.Context, host string) ([]net.IP, error) {
		if ips, ok := dns[host]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("no such host")
	}}

	tests := []struct {
		host    string
		wantErr bool
	}{
		{"my-svc.my-ns", false},
		{"my-svc.my-ns.svc.cluster.local", false},
		{"pod.eks-secondary", false},
		{"example.com", true}, // used to pass as "name.namespace" without resolving
		{"ext.my-ns.svc.cluster.local", true},
		{"169.254.169.254", true},
		{"split.my-ns", true},
		{"unknown.my-ns", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			err := tk.validateClusterInternal(context.Background(), tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateClusterInternal(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
		})
	}
}

// The dialer checks the address actually connected to, so a name that
// validated against a cluster IP but connects elsewhere (DNS rebinding) is
// refused. The test server listens on loopback, which isn't a cluster IP.
func TestGuardedClientBlocksNonClusterConnect(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer server.Close()

	tk := &Task{
		httpClient: func(timeout time.Duration) *http.Client { return newGuardedClient(timeout, isClusterIP) },
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil // lies: validation passes
		},
	}
	payload, _ := json.Marshal(Payload{Method: "GET", URL: server.URL})
	result, err := tk.Execute(context.Background(), payload)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Success || !strings.Contains(result.Error, "non-cluster address blocked") {
		t.Fatalf("connection to a non-cluster address was not blocked: success=%v error=%q", result.Success, result.Error)
	}
	if hit {
		t.Fatal("the request reached the server")
	}
}

// Redirects are returned to the caller, not followed to another host.
func TestGuardedClientDoesNotFollowRedirects(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHit = true }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer origin.Close()

	tk := &Task{
		// Allow loopback here so only the redirect behaviour is under test.
		httpClient: func(timeout time.Duration) *http.Client {
			return newGuardedClient(timeout, func(ip net.IP) bool { return ip.IsLoopback() })
		},
		resolver: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1")}, nil
		},
	}
	payload, _ := json.Marshal(Payload{Method: "GET", URL: origin.URL})
	result, err := tk.Execute(context.Background(), payload)
	if err != nil || !result.Success {
		t.Fatalf("Execute() err=%v result=%+v", err, result)
	}
	if targetHit {
		t.Fatal("redirect was followed")
	}
	var details HTTPResult
	raw, _ := json.Marshal(result.Details)
	_ = json.Unmarshal(raw, &details)
	if details.StatusCode != http.StatusFound || !strings.Contains(details.Headers["Location"], "/latest/meta-data/") {
		t.Fatalf("want the 302 and its Location returned, got %d %v", details.StatusCode, details.Headers)
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
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"169.254.169.254", false}, // cloud metadata service
		{"127.0.0.1", false},
		{"100.128.0.1", false},
		{"::ffff:10.0.0.1", true},
		{"::1", false},
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
