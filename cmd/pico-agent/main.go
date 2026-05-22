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
	"github.com/loafoe/pico-agent/internal/task/list_gateways"
	"github.com/loafoe/pico-agent/internal/task/list_ingresses"
	"github.com/loafoe/pico-agent/internal/task/list_namespaces"
	"github.com/loafoe/pico-agent/internal/task/list_pods"
	"github.com/loafoe/pico-agent/internal/task/list_pvcs"
	"github.com/loafoe/pico-agent/internal/task/list_routes"
	"github.com/loafoe/pico-agent/internal/task/list_services"
	"github.com/loafoe/pico-agent/internal/task/pod_resource_usage"
	"github.com/loafoe/pico-agent/internal/task/list_workloads"
	"github.com/loafoe/pico-agent/internal/task/pv_resize"
	"github.com/loafoe/pico-agent/internal/task/pv_resize_status"
	"github.com/loafoe/pico-agent/internal/task/pv_usage"
	"github.com/loafoe/pico-agent/internal/task/resource_pressure"
	"github.com/loafoe/pico-agent/internal/task/storage_status"
	"github.com/loafoe/pico-agent/internal/task/connectivity_test"
	"github.com/loafoe/pico-agent/internal/task/dns_check"
	"github.com/loafoe/pico-agent/internal/task/list_endpoints"
	"github.com/loafoe/pico-agent/internal/task/list_network_policies"
	"github.com/loafoe/pico-agent/internal/task/pod_evict"
	"github.com/loafoe/pico-agent/internal/task/pod_resize"
	"github.com/loafoe/pico-agent/internal/task/list_argocd_applications"
	"github.com/loafoe/pico-agent/internal/task/list_nodeclaims"
	"github.com/loafoe/pico-agent/internal/task/list_nodepools"
	"github.com/loafoe/pico-agent/internal/task/list_vpas"
	"github.com/loafoe/pico-agent/internal/task/nodeclaim_delete"
	"github.com/loafoe/pico-agent/internal/task/workload_restart"
	"github.com/loafoe/pico-agent/internal/task/workload_scale"
	"github.com/loafoe/pico-agent/internal/task/http_request"
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

	if cfg.AllowUnauthenticated {
		slog.Warn("running without authentication - development mode only")
	}

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
	registry.Register(cluster_info.New(k8sClient.Clientset).WithCapabilities(cluster_info.Capabilities{
		WorkloadRestart: cfg.Features.WorkloadRestartEnabled,
		WorkloadScale:   cfg.Features.WorkloadScaleEnabled,
		PodEvict:        cfg.Features.PodEvictEnabled,
		PodResize:       cfg.Features.PodResizeEnabled,
		GetResource:     cfg.Features.GetResourceEnabled,
		NodeclaimDelete: cfg.Features.NodeclaimDeleteEnabled,
		Argocd:          cfg.Features.ArgocdEnabled,
		PvResize:        cfg.Features.PvResizeEnabled,
		AutoRemediate:   cfg.Features.AutoRemediateEnabled,
	}))
	registry.Register(cluster_health.New(k8sClient.Clientset))
	registry.Register(resource_pressure.New(k8sClient.Clientset))
	registry.Register(storage_status.New(k8sClient.Clientset))
	registry.Register(list_namespaces.New(k8sClient.Clientset))
	registry.Register(pv_usage.New(k8sClient.Clientset))
	registry.Register(list_pods.New(k8sClient.Clientset))
	registry.Register(list_pvcs.New(k8sClient.Clientset))
	registry.Register(get_logs.New(k8sClient.Clientset))
	registry.Register(list_workloads.New(k8sClient.Clientset))
	registry.Register(get_events.New(k8sClient.Clientset))
	registry.Register(pod_resource_usage.New(k8sClient.Clientset))
	registry.Register(list_services.New(k8sClient.Clientset))
	registry.Register(list_ingresses.New(k8sClient.Clientset))
	registry.Register(list_gateways.New(k8sClient.DynamicClient))
	registry.Register(list_routes.New(k8sClient.DynamicClient))
	registry.Register(list_endpoints.New(k8sClient.Clientset))
	registry.Register(list_network_policies.New(k8sClient.Clientset))
	registry.Register(dns_check.New())
	registry.Register(connectivity_test.New())
	registry.Register(list_nodeclaims.New(k8sClient.DynamicClient))
	registry.Register(list_nodepools.New(k8sClient.DynamicClient))
	registry.Register(list_vpas.New(k8sClient.Clientset, k8sClient.DynamicClient))

	// Optional: get_resource task (requires expanded RBAC)
	if cfg.Features.GetResourceEnabled {
		registry.Register(get_resource.New(k8sClient.DynamicClient, k8sClient.RESTMapper))
		slog.Info("get_resource task enabled")
	}

	// Optional: workload_restart task (write operation)
	if cfg.Features.WorkloadRestartEnabled {
		registry.Register(workload_restart.New(k8sClient.Clientset))
		slog.Info("workload_restart task enabled")
	}

	// Optional: workload_scale task (write operation)
	if cfg.Features.WorkloadScaleEnabled {
		registry.Register(workload_scale.New(k8sClient.Clientset))
		slog.Info("workload_scale task enabled")
	}

	// Optional: pod_evict task (write operation)
	if cfg.Features.PodEvictEnabled {
		registry.Register(pod_evict.New(k8sClient.Clientset))
		slog.Info("pod_evict task enabled")
	}

	// Optional: pod_resize task (write operation, requires K8s 1.27+)
	if cfg.Features.PodResizeEnabled {
		registry.Register(pod_resize.New(k8sClient.Clientset, cfg.Features.PodResizeConfig))
		slog.Info("pod_resize task enabled")
	}

	// Optional: nodeclaim_delete task (Karpenter node management)
	if cfg.Features.NodeclaimDeleteEnabled {
		registry.Register(nodeclaim_delete.New(k8sClient.DynamicClient))
		slog.Info("nodeclaim_delete task enabled")
	}

	// Optional: list_argocd_applications task (Argo CD introspection)
	if cfg.Features.ArgocdEnabled {
		registry.Register(list_argocd_applications.New(k8sClient.DynamicClient))
		slog.Info("list_argocd_applications task enabled")
	}

	// Optional: http_request task (cluster-internal HTTP requests)
	if cfg.Features.HTTPRequestEnabled {
		registry.Register(http_request.New())
		slog.Info("http_request task enabled")
	}

	// Optional: pv_resize task (storage write operation)
	if cfg.Features.PvResizeEnabled {
		registry.Register(pv_resize.New(k8sClient.Clientset))
		registry.Register(pv_resize_status.New(k8sClient.Clientset))
		slog.Info("pv_resize task enabled")
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
		metrics,
		spireClient,
		Version,
		cfg.AllowUnauthenticated,
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
