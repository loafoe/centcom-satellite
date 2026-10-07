package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/config"
	"github.com/loafoe/centcom-satellite/internal/observability"
	"github.com/loafoe/centcom-satellite/internal/spire"
	"github.com/loafoe/centcom-satellite/internal/task"
)

// Config holds server configuration.
type Config struct {
	Port        int
	MetricsPort int
	RateLimit   config.RateLimitConfig
}

// Server is the main HTTP server.
type Server struct {
	config         Config
	handlers       *Handlers
	streamHandlers *StreamHandlers
	metrics        *observability.Metrics
	spireClient    *spire.Client
	version        string
	main           *http.Server
	mux            *http.Server
}

// New creates a new server instance.
func New(cfg Config, registry *task.Registry, metrics *observability.Metrics, spireClient *spire.Client, version string, allowUnauthenticated bool, k8sClientset kubernetes.Interface) *Server {
	handlers := NewHandlers(registry, spireClient, metrics, version, allowUnauthenticated)
	streamHandlers := NewStreamHandlers(k8sClientset, spireClient, metrics, allowUnauthenticated)

	return &Server{
		config:         cfg,
		handlers:       handlers,
		streamHandlers: streamHandlers,
		metrics:        metrics,
		spireClient:    spireClient,
		version:        version,
	}
}

// Start starts both the main and metrics servers.
func (s *Server) Start(ctx context.Context) error {
	// Main server routes
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/task", s.handlers.HandleTask)
	mainMux.HandleFunc("/tasks", s.handlers.HandleListTasks)
	mainMux.HandleFunc("/healthz", s.handlers.HandleHealthz)
	mainMux.HandleFunc("/readyz", s.handlers.HandleReadyz)
	mainMux.HandleFunc("/version", s.handlers.HandleVersion)
	mainMux.HandleFunc("/info", s.handlers.HandleInfo)
	mainMux.HandleFunc("/logs/stream", s.streamHandlers.HandleLogStream)

	// Apply middleware. LoggingMiddleware must wrap RateLimitMiddleware
	// (i.e. come first here — Chain makes earlier entries more "outer") so a
	// rejected (429) request still gets logged: it calls next.ServeHTTP and
	// then logs the final status, so it runs regardless of what the rate
	// limiter, as its "next", decides to do.
	mainHandler := Chain(
		mainMux,
		RecoveryMiddleware,
		TracingMiddleware,
		MetricsMiddleware(s.metrics),
		LoggingMiddleware,
		RateLimitMiddleware(s.config.RateLimit),
	)

	s.main = &http.Server{
		Addr:        fmt.Sprintf(":%d", s.config.Port),
		Handler:     mainHandler,
		ReadTimeout: 15 * time.Second,
		// Raised 30s -> 60s (2026-10-07): this is a blanket cutoff shared by
		// every task type, but pv_usage's own worst case (every node timing
		// out) was already close to - and on some real clusters, past - the
		// old 30s value; see pv_usage.nodeStatsConcurrency's doc comment for
		// the exact math. 60s gives headroom for that task's revised worst
		// case plus genuinely large clusters, without being so long that a
		// truly hung handler ties up a connection indefinitely.
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", s.handlers.HandleHealthz)
	metricsMux.HandleFunc("/readyz", s.handlers.HandleReadyz)

	s.mux = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.MetricsPort),
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start metrics server
	go func() {
		slog.Info("starting metrics server", "port", s.config.MetricsPort)
		if err := s.mux.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "error", err)
		}
	}()

	// Start main server (with or without SPIRE mTLS)
	// Use mTLS only if both SPIRE is enabled AND mTLS is enabled
	// JWT-SVID auth can work without mTLS (over plain HTTP with TLS termination at gateway)
	if s.spireClient != nil && s.spireClient.IsMTLSEnabled() {
		return s.startWithSPIRE()
	}

	return s.startPlain()
}

// startPlain starts the server without TLS.
func (s *Server) startPlain() error {
	slog.Info("starting main server (plain HTTP)", "port", s.config.Port)
	if err := s.main.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("main server error: %w", err)
	}
	return nil
}

// startWithSPIRE starts the server with SPIRE mTLS.
func (s *Server) startWithSPIRE() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	tlsListener, err := s.spireClient.WrapListener(listener)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to wrap listener with SPIRE TLS: %w", err)
	}

	allowedIDs := s.spireClient.GetAllowedIDs()
	if len(allowedIDs) > 0 {
		slog.Info("starting main server (SPIRE mTLS)",
			"port", s.config.Port,
			"allowed_spiffe_ids", allowedIDs,
		)
	} else {
		slog.Info("starting main server (SPIRE mTLS, any valid SVID)",
			"port", s.config.Port,
		)
	}

	if err := s.main.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("main server error: %w", err)
	}
	return nil
}

// Shutdown gracefully stops both servers.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down servers")

	// Shutdown main server
	if err := s.main.Shutdown(ctx); err != nil {
		slog.Error("main server shutdown error", "error", err)
	}

	// Shutdown metrics server
	if err := s.mux.Shutdown(ctx); err != nil {
		slog.Error("metrics server shutdown error", "error", err)
	}

	return nil
}
