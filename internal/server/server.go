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

	"github.com/loafoe/centcom-satellite/internal/observability"
	"github.com/loafoe/centcom-satellite/internal/spire"
	"github.com/loafoe/centcom-satellite/internal/task"
)

// Config holds server configuration.
type Config struct {
	Port        int
	MetricsPort int
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

	// Apply middleware
	mainHandler := Chain(
		mainMux,
		RecoveryMiddleware,
		TracingMiddleware,
		MetricsMiddleware(s.metrics),
		LoggingMiddleware,
	)

	s.main = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Port),
		Handler:      mainHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())

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
