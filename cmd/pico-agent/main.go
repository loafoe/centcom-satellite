// Package main is the entry point for pico-agent.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/loafoe/pico-agent/internal/config"
	"github.com/loafoe/pico-agent/internal/k8s"
	"github.com/loafoe/pico-agent/internal/observability"
	"github.com/loafoe/pico-agent/internal/server"
	"github.com/loafoe/pico-agent/internal/spire"
	"github.com/loafoe/pico-agent/internal/task"
	"github.com/loafoe/pico-agent/internal/task/cluster_health"
	"github.com/loafoe/pico-agent/internal/task/cluster_info"
	"github.com/loafoe/pico-agent/internal/task/get_events"
	"github.com/loafoe/pico-agent/internal/task/get_logs"
	"github.com/loafoe/pico-agent/internal/task/get_resource"
	"github.com/loafoe/pico-agent/internal/task/list_namespaces"
	"github.com/loafoe/pico-agent/internal/task/list_pods"
	"github.com/loafoe/pico-agent/internal/task/pod_resource_usage"
	"github.com/loafoe/pico-agent/internal/task/list_workloads"
	"github.com/loafoe/pico-agent/internal/task/pv_resize"
	"github.com/loafoe/pico-agent/internal/task/pv_resize_status"
	"github.com/loafoe/pico-agent/internal/task/pv_usage"
	"github.com/loafoe/pico-agent/internal/task/resource_pressure"
	"github.com/loafoe/pico-agent/internal/task/storage_status"
	"github.com/loafoe/pico-agent/internal/webhook"
)

// Version is set at build time.
var Version = "dev"

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Setup logging
	observability.SetupLogging(cfg.LogLevel, cfg.LogFormat)
	slog.Info("starting pico-agent", "version", Version)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup tracing
	shutdownTracing, err := observability.SetupTracing(ctx, cfg.OTelServiceName, Version, cfg.OTelEndpoint)
	if err != nil {
		slog.Error("failed to setup tracing", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			slog.Error("failed to shutdown tracing", "error", err)
		}
	}()

	// Setup metrics
	metrics := observability.NewMetrics()

	// Setup Kubernetes client
	k8sClient, err := k8s.NewClient()
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	// Setup task registry
	registry := task.NewRegistry()
	registry.Register(pv_resize.New(k8sClient.Clientset))
	registry.Register(pv_resize_status.New(k8sClient.Clientset))
	registry.Register(cluster_info.New(k8sClient.Clientset))
	registry.Register(cluster_health.New(k8sClient.Clientset))
	registry.Register(resource_pressure.New(k8sClient.Clientset))
	registry.Register(storage_status.New(k8sClient.Clientset))
	registry.Register(list_namespaces.New(k8sClient.Clientset))
	registry.Register(pv_usage.New(k8sClient.Clientset))
	registry.Register(list_pods.New(k8sClient.Clientset))
	registry.Register(get_logs.New(k8sClient.Clientset))
	registry.Register(list_workloads.New(k8sClient.Clientset))
	registry.Register(get_events.New(k8sClient.Clientset))
	registry.Register(pod_resource_usage.New(k8sClient.Clientset))

	// Optional: get_resource task (requires expanded RBAC)
	if cfg.Features.GetResourceEnabled {
		registry.Register(get_resource.New(k8sClient.DynamicClient, k8sClient.RESTMapper))
		slog.Info("get_resource task enabled")
	}

	// Setup webhook verifier (may be nil if SPIRE-only auth)
	var verifier *webhook.Verifier
	if cfg.WebhookSecret != "" {
		verifier = webhook.NewVerifier(cfg.WebhookSecret)
	}

	// Setup SPIRE client if enabled
	var spireClient *spire.Client
	if cfg.SPIRE.Enabled {
		spireClient = spire.NewClient(&cfg.SPIRE)
		if err := spireClient.Start(ctx); err != nil {
			slog.Error("failed to start SPIRE client", "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := spireClient.Close(); err != nil {
				slog.Error("failed to close SPIRE client", "error", err)
			}
		}()
	}

	// Create and start server
	srv := server.New(
		server.Config{
			Port:        cfg.Port,
			MetricsPort: cfg.MetricsPort,
		},
		registry,
		verifier,
		metrics,
		spireClient,
		Version,
	)

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start(ctx)
	}()

	// Wait for interrupt signal or server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig)
	case err := <-serverErrors:
		if err != nil {
			slog.Error("server error", "error", err)
		}
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	slog.Info("shutdown complete")
}
