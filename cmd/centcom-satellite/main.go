// Package main is the entry point for centcom-satellite.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"

	awshelper "github.com/loafoe/centcom-satellite/internal/aws"
	"github.com/loafoe/centcom-satellite/internal/config"
	"github.com/loafoe/centcom-satellite/internal/k8s"
	"github.com/loafoe/centcom-satellite/internal/observability"
	"github.com/loafoe/centcom-satellite/internal/server"
	"github.com/loafoe/centcom-satellite/internal/spire"
	"github.com/loafoe/centcom-satellite/internal/task"
	"github.com/loafoe/centcom-satellite/internal/task/account_info"
	"github.com/loafoe/centcom-satellite/internal/task/cluster_health"
	"github.com/loafoe/centcom-satellite/internal/task/cluster_info"
	"github.com/loafoe/centcom-satellite/internal/task/connectivity_test"
	"github.com/loafoe/centcom-satellite/internal/task/cost_explorer"
	"github.com/loafoe/centcom-satellite/internal/task/cw_alarm_history"
	"github.com/loafoe/centcom-satellite/internal/task/cw_describe_log_groups"
	"github.com/loafoe/centcom-satellite/internal/task/cw_get_metrics"
	"github.com/loafoe/centcom-satellite/internal/task/cw_list_alarms"
	"github.com/loafoe/centcom-satellite/internal/task/cw_list_metrics"
	"github.com/loafoe/centcom-satellite/internal/task/cw_logs_query"
	"github.com/loafoe/centcom-satellite/internal/task/dns_check"
	"github.com/loafoe/centcom-satellite/internal/task/get_configmap"
	"github.com/loafoe/centcom-satellite/internal/task/get_events"
	"github.com/loafoe/centcom-satellite/internal/task/get_logs"
	"github.com/loafoe/centcom-satellite/internal/task/get_resource"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_findings"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_get_findings"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_get_findings_statistics"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_list_detectors"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_list_findings"
	"github.com/loafoe/centcom-satellite/internal/task/http_request"
	"github.com/loafoe/centcom-satellite/internal/task/list_argocd_applications"
	"github.com/loafoe/centcom-satellite/internal/task/list_configmaps"
	"github.com/loafoe/centcom-satellite/internal/task/list_endpoints"
	"github.com/loafoe/centcom-satellite/internal/task/list_gateways"
	"github.com/loafoe/centcom-satellite/internal/task/list_ingresses"
	"github.com/loafoe/centcom-satellite/internal/task/list_namespaces"
	"github.com/loafoe/centcom-satellite/internal/task/list_network_policies"
	"github.com/loafoe/centcom-satellite/internal/task/list_nodeclaims"
	"github.com/loafoe/centcom-satellite/internal/task/list_nodepools"
	"github.com/loafoe/centcom-satellite/internal/task/list_pods"
	"github.com/loafoe/centcom-satellite/internal/task/list_pvcs"
	"github.com/loafoe/centcom-satellite/internal/task/list_routes"
	"github.com/loafoe/centcom-satellite/internal/task/list_services"
	"github.com/loafoe/centcom-satellite/internal/task/list_vpas"
	"github.com/loafoe/centcom-satellite/internal/task/list_workloads"
	"github.com/loafoe/centcom-satellite/internal/task/nodeclaim_delete"
	"github.com/loafoe/centcom-satellite/internal/task/pod_evict"
	"github.com/loafoe/centcom-satellite/internal/task/pod_resize"
	"github.com/loafoe/centcom-satellite/internal/task/pod_resource_usage"
	"github.com/loafoe/centcom-satellite/internal/task/pv_resize"
	"github.com/loafoe/centcom-satellite/internal/task/pv_resize_status"
	"github.com/loafoe/centcom-satellite/internal/task/pv_usage"
	"github.com/loafoe/centcom-satellite/internal/task/resource_pressure"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_get_findings"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_get_findings_statistics"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_get_insight_statistics"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_list_standards"
	"github.com/loafoe/centcom-satellite/internal/task/securityhub_update_findings"
	"github.com/loafoe/centcom-satellite/internal/task/storage_status"
	"github.com/loafoe/centcom-satellite/internal/task/workload_restart"
	"github.com/loafoe/centcom-satellite/internal/task/workload_scale"
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
	slog.Info("starting centcom-satellite", "version", Version)

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
	metrics.SetBuildInfo(Version)

	// Setup cross-account AWS AssumeRole credentials, if configured. A
	// no-op when AWS_ASSUME_ROLE_ARN is unset. Fails fast — misconfigured
	// trust policies/ExternalId must not surface only on the first task
	// call. Determined before the Kubernetes client below: when AssumeRole
	// is configured, this satellite runs in AWS-only mode — it may not be
	// running inside (or connected to) a Kubernetes cluster at all, so no
	// Kubernetes client is created and no control-plane task is
	// registered. SPIFFE/SPIRE caller authentication (further below) is
	// unaffected either way — AWS-only mode disables Kubernetes
	// control-plane tasks, not authentication.
	if err := awshelper.Init(ctx, awshelper.AssumeRoleOptions{
		ARN:         cfg.AWSAssumeRole.ARN,
		ExternalID:  cfg.AWSAssumeRole.ExternalID,
		SessionName: cfg.AWSAssumeRole.SessionName,
	}); err != nil {
		slog.Error("failed to configure cross-account AWS AssumeRole", "error", err)
		os.Exit(1)
	}
	awsOnlyMode := cfg.AWSAssumeRole.ARN != ""

	// Setup Kubernetes client (instrumented with Prometheus metrics), unless
	// AssumeRole put this satellite in AWS-only mode.
	var k8sClient *k8s.Client
	if !awsOnlyMode {
		k8sClient, err = k8s.NewClient(metrics)
		if err != nil {
			slog.Error("failed to create kubernetes client", "error", err)
			os.Exit(1)
		}
	} else {
		slog.Info("AWS-only mode (AWS_ASSUME_ROLE_ARN set): skipping Kubernetes client and control-plane tasks")
	}

	// capabilities advertises which optional task groups are enabled on this
	// agent. Purely config-derived (no Kubernetes dependency), so it's
	// computed once and reported by both account_info (always registered)
	// and cluster_info (Kubernetes mode only) — account_info is the only
	// capabilities source on a cluster-less (AWS-only AssumeRole) satellite.
	capabilities := cluster_info.Capabilities{
		WorkloadRestart:  cfg.Features.WorkloadRestartEnabled,
		WorkloadScale:    cfg.Features.WorkloadScaleEnabled,
		PodEvict:         cfg.Features.PodEvictEnabled,
		PodResize:        cfg.Features.PodResizeEnabled,
		GetResource:      cfg.Features.GetResourceEnabled,
		NodeclaimDelete:  cfg.Features.NodeclaimDeleteEnabled,
		Argocd:           cfg.Features.ArgocdEnabled,
		PvResize:         cfg.Features.PvResizeEnabled,
		AutoRemediate:    cfg.Features.AutoRemediateEnabled,
		HttpRequest:      cfg.Features.HTTPRequestEnabled,
		ConfigmapRead:    cfg.Features.ConfigmapReadEnabled,
		CloudWatchRCA:    cfg.Features.CloudWatchRCAEnabled,
		GuardDuty:        cfg.Features.GuardDutyEnabled,
		SecurityHub:      cfg.Features.SecurityHubEnabled,
		SecurityHubWrite: cfg.Features.SecurityHubWriteEnabled,
	}

	// Setup task registry
	registry := task.NewRegistry()
	registry.Register(account_info.New(cfg.AWSAssumeRole.ARN).WithCapabilities(capabilities))
	registry.Register(dns_check.New())
	registry.Register(connectivity_test.New())

	if !awsOnlyMode {
		registry.Register(cluster_info.New(k8sClient.Clientset).WithCapabilities(capabilities))
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

		// Optional: ConfigMap introspection tasks (list metadata + read redacted values)
		if cfg.Features.ConfigmapReadEnabled {
			registry.Register(list_configmaps.New(k8sClient.Clientset))
			registry.Register(get_configmap.New(k8sClient.Clientset))
			slog.Info("list_configmaps and get_configmap tasks enabled")
		}

		// Optional: pv_resize task (storage write operation)
		if cfg.Features.PvResizeEnabled {
			registry.Register(pv_resize.New(k8sClient.Clientset))
			registry.Register(pv_resize_status.New(k8sClient.Clientset))
			slog.Info("pv_resize task enabled")
		}
	}

	// Optional: http_request task (arbitrary HTTP requests). No Kubernetes
	// dependency — available in both modes.
	if cfg.Features.HTTPRequestEnabled {
		registry.Register(http_request.New())
		slog.Info("http_request task enabled")
	}

	// Optional: CloudWatch RCA data-retrieval tasks (require AWS credentials + IAM)
	if cfg.Features.CloudWatchRCAEnabled {
		registry.Register(cw_list_alarms.New())
		registry.Register(cw_alarm_history.New())
		registry.Register(cw_get_metrics.New())
		registry.Register(cw_list_metrics.New())
		registry.Register(cw_describe_log_groups.New())
		registry.Register(cw_logs_query.New())
		registry.Register(cost_explorer.New())
		slog.Info("cloudwatch RCA tasks enabled",
			"tasks", "cw_list_alarms,cw_alarm_history,cw_get_metrics,cw_list_metrics,cw_describe_log_groups,cw_logs_query,cost_explorer")
	}

	// Optional: GuardDuty data-retrieval tasks (require AWS credentials + read-only
	// GuardDuty IAM; see deploy/iam-policy-guardduty.json). Independently toggleable
	// from CloudWatch RCA so a cluster can enable GuardDuty without CloudWatch access.
	if cfg.Features.GuardDutyEnabled {
		registry.Register(guardduty_list_detectors.New())
		registry.Register(guardduty_get_findings_statistics.New())
		registry.Register(guardduty_list_findings.New())
		registry.Register(guardduty_get_findings.New())
		registry.Register(guardduty_findings.New())
		slog.Info("guardduty tasks enabled",
			"tasks", "guardduty_list_detectors,guardduty_get_findings_statistics,guardduty_list_findings,guardduty_get_findings,guardduty_findings")
	}

	// Optional: Security Hub data-retrieval tasks (require AWS credentials +
	// read-only Security Hub IAM; see deploy/iam-policy-securityhub.json).
	// Independently toggleable from GuardDuty/CloudWatch RCA — Security Hub
	// aggregates findings from more products and, unlike GuardDuty, supports
	// updating a finding's Workflow.Status via the separate write flag below.
	if cfg.Features.SecurityHubEnabled {
		registry.Register(securityhub_list_standards.New())
		registry.Register(securityhub_get_findings.New())
		registry.Register(securityhub_get_findings_statistics.New())
		registry.Register(securityhub_get_insight_statistics.New())
		slog.Info("securityhub tasks enabled",
			"tasks", "securityhub_list_standards,securityhub_get_findings,securityhub_get_findings_statistics,securityhub_get_insight_statistics")
	}

	// Optional: Security Hub write task (BatchUpdateFindings). Gated
	// separately from SecurityHubEnabled so a cluster can grant read-only
	// triage visibility without write access; see
	// deploy/iam-policy-securityhub-write.json.
	if cfg.Features.SecurityHubWriteEnabled {
		registry.Register(securityhub_update_findings.New())
		slog.Info("securityhub_update_findings task enabled")
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
	var k8sClientset kubernetes.Interface
	if k8sClient != nil {
		k8sClientset = k8sClient.Clientset
	}
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
		k8sClientset,
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
