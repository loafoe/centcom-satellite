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
	"github.com/loafoe/centcom-satellite/internal/task/aws_read"
	"github.com/loafoe/centcom-satellite/internal/task/cloudtrail_logins"
	"github.com/loafoe/centcom-satellite/internal/task/cloudtrail_lookup_events"
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
	"github.com/loafoe/centcom-satellite/internal/task/get_events"
	"github.com/loafoe/centcom-satellite/internal/task/get_logs"
	"github.com/loafoe/centcom-satellite/internal/task/get_resource"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_findings"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_get_findings"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_get_findings_statistics"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_list_detectors"
	"github.com/loafoe/centcom-satellite/internal/task/guardduty_list_findings"
	"github.com/loafoe/centcom-satellite/internal/task/helm_application"
	"github.com/loafoe/centcom-satellite/internal/task/http_request"
	"github.com/loafoe/centcom-satellite/internal/task/list_argocd_applications"
	"github.com/loafoe/centcom-satellite/internal/task/list_configmaps"
	"github.com/loafoe/centcom-satellite/internal/task/list_endpoints"
	"github.com/loafoe/centcom-satellite/internal/task/list_gateways"
	"github.com/loafoe/centcom-satellite/internal/task/list_hpas"
	"github.com/loafoe/centcom-satellite/internal/task/list_ingresses"
	"github.com/loafoe/centcom-satellite/internal/task/list_namespaces"
	"github.com/loafoe/centcom-satellite/internal/task/list_network_policies"
	"github.com/loafoe/centcom-satellite/internal/task/list_nodeclaims"
	"github.com/loafoe/centcom-satellite/internal/task/list_nodepools"
	"github.com/loafoe/centcom-satellite/internal/task/list_pdbs"
	"github.com/loafoe/centcom-satellite/internal/task/list_pods"
	"github.com/loafoe/centcom-satellite/internal/task/list_pvcs"
	"github.com/loafoe/centcom-satellite/internal/task/list_resources"
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
	"github.com/loafoe/centcom-satellite/internal/task/resourceaccess"
	"github.com/loafoe/centcom-satellite/internal/task/running_image_vulnerabilities"
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
		Region:      cfg.AWSAssumeRole.Region,
	}); err != nil {
		slog.Error("failed to configure cross-account AWS AssumeRole", "error", err)
		os.Exit(1)
	}
	awsOnlyMode := cfg.AWSAssumeRole.ARN != ""

	// account_info is otherwise unconditionally registered below regardless
	// of whether this satellite has any AWS integration at all. On a
	// satellite with none (e.g. a homelab/on-prem cluster: no IRSA, no
	// IMDS, no explicit keys), every account_info call used to ride out the
	// AWS SDK's full IMDS retry/timeout chain (~5s) before failing - and
	// still showed up in list_tasks as if it worked. awsOnlyMode already
	// proves credentials are real here (Init's own verifyCallerIdentity
	// call above would have os.Exit(1) otherwise); HasCredentials() is the
	// cheap, synchronous, no-network-call signal for every other case -
	// IRSA/Pod Identity env vars or token file, matching how every
	// satellite in this fleet actually gets AWS credentials (no fleet
	// satellite relies on a bare EC2 instance-profile role via node-level
	// IMDS passthrough).
	awsCredentialsAvailable := awsOnlyMode || awshelper.HasCredentials()
	if !awsCredentialsAvailable {
		slog.Info("no AWS credentials detected: account_info task will not be registered")
	}

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
	// computed once and reported by both account_info (registered whenever
	// awsCredentialsAvailable, see below) and cluster_info (Kubernetes mode
	// only) — account_info is the only
	// capabilities source on a cluster-less (AWS-only AssumeRole) satellite.
	capabilities := cluster_info.Capabilities{
		WorkloadRestart:      cfg.Features.WorkloadRestartEnabled,
		WorkloadScale:        cfg.Features.WorkloadScaleEnabled,
		PodEvict:             cfg.Features.PodEvictEnabled,
		PodResize:            cfg.Features.PodResizeEnabled,
		GetResource:          cfg.Features.GetResourceEnabled,
		NodeclaimDelete:      cfg.Features.NodeclaimDeleteEnabled,
		Argocd:               cfg.Features.ArgocdEnabled,
		PvResize:             cfg.Features.PvResizeEnabled,
		AutoRemediate:        cfg.Features.AutoRemediateEnabled,
		HttpRequest:          cfg.Features.HTTPRequestEnabled,
		CloudWatchRCA:        cfg.Features.CloudWatchRCAEnabled,
		GuardDuty:            cfg.Features.GuardDutyEnabled,
		SecurityHub:          cfg.Features.SecurityHubEnabled,
		SecurityHubWrite:     cfg.Features.SecurityHubWriteEnabled,
		CloudTrail:           cfg.Features.CloudTrailEnabled,
		AWSRead:              cfg.Features.AWSReadEnabled,
		HelmApplicationWrite: cfg.Features.HelmApplicationWriteEnabled,
	}

	// Setup task registry. Extracted into registerTasks so the
	// flag->registration wiring (in particular, that every write-capable
	// task is only reachable when its own Features.*Enabled flag is true)
	// is covered by an automated test instead of relying on manual code
	// review - see TestRegisterTasks_* in main_test.go.
	registry := registerTasks(cfg, k8sClient, awsOnlyMode, awsCredentialsAvailable, capabilities)

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
			RateLimit:   cfg.RateLimit,
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

// registerTasks builds the task registry, gating each optional task behind
// its own cfg.Features.*Enabled flag. This is the sole runtime enforcement
// point for the read-only/write-mode boundary: a task whose flag is false is
// never added to the registry, so any call for it fails with
// task.ErrTaskNotFound (see registry.Execute) regardless of caller
// permissions - there is no separate RBAC/allowlist check inside the write
// tasks themselves. See TestRegisterTasks_* in main_test.go, which locks
// this behavior in per-flag and against install.sh's READ_ONLY=true default
// feature set.
//
// awsCredentialsAvailable gates account_info specifically: unlike every
// other task here, it has no Features.*Enabled flag of its own - it's meant
// to always be on, but only actually makes sense when this satellite has
// some AWS identity to report. Deciding this once at startup (not inside
// account_info.Execute itself) keeps list_tasks honest - a task that isn't
// registered doesn't appear in the catalog at all, and a call for it fails
// immediately via the same task.ErrTaskNotFound path every other
// not-registered task already uses, with no per-call credential probe.
func registerTasks(cfg *config.Config, k8sClient *k8s.Client, awsOnlyMode bool, awsCredentialsAvailable bool, capabilities cluster_info.Capabilities) *task.Registry {
	registry := task.NewRegistry()
	if awsCredentialsAvailable {
		registry.Register(account_info.New(cfg.AWSAssumeRole.ARN).WithCapabilities(capabilities))
	}
	registry.Register(dns_check.New())
	registry.Register(connectivity_test.New())

	if !awsOnlyMode {
		registry.Register(cluster_info.New(k8sClient.Clientset).WithCapabilities(capabilities))
		registry.Register(cluster_health.New(k8sClient.Clientset))
		registry.Register(resource_pressure.New(k8sClient.Clientset))
		registry.Register(storage_status.New(k8sClient.Clientset))
		registry.Register(list_namespaces.New(k8sClient.Clientset))
		registry.Register(pv_usage.New(k8sClient.Clientset))
		// ConfigMap metadata listing (names, key names, sizes, age - never
		// values). Unconditional: its RBAC (configmaps get/list) is part of
		// the base ClusterRole, same as the other list_* tasks below. Reading
		// actual values goes through get_resource (kind: ConfigMap).
		registry.Register(list_configmaps.New(k8sClient.Clientset))
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
		registry.Register(list_hpas.New(k8sClient.Clientset))
		registry.Register(list_pdbs.New(k8sClient.Clientset))

		// Optional: get_resource task (requires expanded RBAC - see the
		// chart's view ClusterRoleBinding). denylist always blocks Secret
		// even if ResourceAccessDeny is empty (the common case).
		if cfg.Features.GetResourceEnabled {
			// list_resources shares the exact same Denylist instance as
			// get_resource (not a second New() call) so the exclusion can't
			// be bypassed by listing instead of getting - see
			// resourceaccess.New's doc comment.
			denylist := resourceaccess.New(cfg.Features.ResourceAccessDeny)
			registry.Register(get_resource.New(k8sClient.DynamicClient, k8sClient.RESTMapper, denylist))
			registry.Register(list_resources.New(k8sClient.DynamicClient, k8sClient.RESTMapper, denylist))
			slog.Info("get_resource/list_resources tasks enabled", "denied_kinds", len(cfg.Features.ResourceAccessDeny)+1)
		}

		// helm_application_apply/_delete/_sync are all write operations -
		// apply can create or silently modify any HelmApplication, so it is
		// not gated any more leniently than delete/sync (an earlier version
		// of this code gated apply separately under an always-on flag on
		// the mistaken premise that optimistic concurrency made it safe by
		// default - fixed in code review). All three require the same
		// flag, matching the chart's single features.helmApplicationWrite
		// RBAC gate.
		if cfg.Features.HelmApplicationWriteEnabled {
			registry.Register(helm_application.NewApply(k8sClient.DynamicClient))
			registry.Register(helm_application.NewDelete(k8sClient.DynamicClient))
			registry.Register(helm_application.NewSync(k8sClient.DynamicClient))
			slog.Info("helm_application_apply/_delete/_sync tasks enabled")
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
		// Inspector findings for the images running in this cluster (same
		// findings Security Hub aggregates, joined with the cluster's pods;
		// needs ecr:BatchGetImage + inspector2:ListFindings/ListCoverage).
		if !awsOnlyMode {
			registry.Register(running_image_vulnerabilities.New(k8sClient.Clientset))
			slog.Info("running_image_vulnerabilities task enabled")
		}
	}

	// Optional: Security Hub write task (BatchUpdateFindings). Gated
	// separately from SecurityHubEnabled so a cluster can grant read-only
	// triage visibility without write access; see
	// deploy/iam-policy-securityhub-write.json.
	if cfg.Features.SecurityHubWriteEnabled {
		registry.Register(securityhub_update_findings.New())
		slog.Info("securityhub_update_findings task enabled")
	}

	// Optional: CloudTrail event-history tasks (read-only; require AWS
	// credentials + cloudtrail:LookupEvents, see deploy/iam-policy-cloudtrail.json).
	if cfg.Features.CloudTrailEnabled {
		registry.Register(cloudtrail_lookup_events.New())
		registry.Register(cloudtrail_logins.New())
		slog.Info("cloudtrail tasks enabled", "tasks", "cloudtrail_lookup_events,cloudtrail_logins")
	}

	// Optional: aws_read (allowlisted read-only IAM / Identity Center calls;
	// require AWS credentials + deploy/iam-policy-aws-read.json).
	if cfg.Features.AWSReadEnabled {
		registry.Register(aws_read.New())
		slog.Info("aws_read task enabled", "services", aws_read.Services())
	}

	return registry
}
