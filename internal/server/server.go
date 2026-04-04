package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/loafoe/pico-agent/internal/observability"
	"github.com/loafoe/pico-agent/internal/task"
	"github.com/loafoe/pico-agent/internal/webhook"
)

// Config holds server configuration.
type Config struct {
	Port        int
	MetricsPort int
}

// Server is the main HTTP server.
type Server struct {
	config   Config
	handlers *Handlers
	metrics  *observability.Metrics
	main     *http.Server
	mux      *http.Server
}

// New creates a new server instance.
func New(cfg Config, registry *task.Registry, verifier *webhook.Verifier, metrics *observability.Metrics) *Server {
	handlers := NewHandlers(registry, verifier, metrics)

	return &Server{
		config:   cfg,
		handlers: handlers,
		metrics:  metrics,
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

	// Start main server
	slog.Info("starting main server", "port", s.config.Port)
	if err := s.main.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
