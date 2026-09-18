package main

import (
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/loafoe/centcom-satellite/internal/config"
	"github.com/loafoe/centcom-satellite/internal/k8s"
	"github.com/loafoe/centcom-satellite/internal/task/cluster_info"
)

func newFakeK8sClient() *k8s.Client {
	return &k8s.Client{
		Clientset:     fake.NewSimpleClientset(),
		DynamicClient: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
	}
}

// writeCapableFlags enumerates every task that mutates cluster/AWS state and
// the config field that must be true for it to be reachable. This is the
// list a validation reviewer needs to audit for "can this deployment ever
// perform this write" - each entry here is now backed by an automated
// registration check below, not just a reading of main.go.
var writeCapableFlags = []struct {
	taskName string
	setFlag  func(f *config.FeaturesConfig, v bool)
}{
	{"workload_restart", func(f *config.FeaturesConfig, v bool) { f.WorkloadRestartEnabled = v }},
	{"workload_scale", func(f *config.FeaturesConfig, v bool) { f.WorkloadScaleEnabled = v }},
	{"pod_evict", func(f *config.FeaturesConfig, v bool) { f.PodEvictEnabled = v }},
	{"pod_resize", func(f *config.FeaturesConfig, v bool) { f.PodResizeEnabled = v }},
	{"nodeclaim_delete", func(f *config.FeaturesConfig, v bool) { f.NodeclaimDeleteEnabled = v }},
	{"pv_resize", func(f *config.FeaturesConfig, v bool) { f.PvResizeEnabled = v }},
	{"pv_resize_status", func(f *config.FeaturesConfig, v bool) { f.PvResizeEnabled = v }},
	{"securityhub_update_findings", func(f *config.FeaturesConfig, v bool) { f.SecurityHubWriteEnabled = v }},
}

// TestRegisterTasks_WriteOperationFlags proves, for every write-capable
// task, that flipping its Features.*Enabled flag is what actually controls
// whether the task is reachable through the registry - not merely a
// documented intent. When the flag is false, registry.Get must report the
// task absent, which is exactly what makes registry.Execute return
// task.ErrTaskNotFound for that call (see internal/task/registry.go).
func TestRegisterTasks_WriteOperationFlags(t *testing.T) {
	for _, tt := range writeCapableFlags {
		for _, enabled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/enabled=%v", tt.taskName, enabled), func(t *testing.T) {
				cfg := &config.Config{}
				tt.setFlag(&cfg.Features, enabled)

				registry := registerTasks(cfg, newFakeK8sClient(), false, cluster_info.Capabilities{})

				_, ok := registry.Get(tt.taskName)
				if ok != enabled {
					t.Errorf("registry.Get(%q) present=%v, want %v (Features flag enabled=%v)", tt.taskName, ok, enabled, enabled)
				}
			})
		}
	}
}

// TestRegisterTasks_ReadOnlyDefaultExcludesAllWriteTasks mirrors
// install.sh's READ_ONLY=true default FEATURES string (helm-charts repo,
// charts/centcom-satellite/install.sh) and asserts that none of the
// write-capable tasks are registered under it. This is the automated,
// regression-protected version of the "read-only boundary" claim -
// previously verified only by manually reading main.go and install.sh
// side by side.
func TestRegisterTasks_ReadOnlyDefaultExcludesAllWriteTasks(t *testing.T) {
	cfg := &config.Config{
		Features: config.FeaturesConfig{
			// Non-mutating tasks the READ_ONLY=true default leaves on.
			GetResourceEnabled: true,
			ArgocdEnabled:      true,
			HTTPRequestEnabled: true,
			// Every write-capable flag is left at its zero value (false),
			// matching install.sh's READ_ONLY=true FEATURES default.
		},
	}

	registry := registerTasks(cfg, newFakeK8sClient(), false, cluster_info.Capabilities{})

	for _, tt := range writeCapableFlags {
		if _, ok := registry.Get(tt.taskName); ok {
			t.Errorf("write-capable task %q is registered under the READ_ONLY=true default feature set - read-only boundary violated", tt.taskName)
		}
	}
}

// TestRegisterTasks_AWSOnlyModeSkipsKubernetesWriteTasks proves that
// AWS-only satellites (no Kubernetes client at all - see AWSAssumeRole
// handling in main) can never register any Kubernetes-targeting write task
// regardless of Features flags, since k8sClient is nil in that mode and the
// entire block is skipped.
func TestRegisterTasks_AWSOnlyModeSkipsKubernetesWriteTasks(t *testing.T) {
	cfg := &config.Config{
		Features: config.FeaturesConfig{
			WorkloadRestartEnabled: true,
			WorkloadScaleEnabled:   true,
			PodEvictEnabled:        true,
			PodResizeEnabled:       true,
			NodeclaimDeleteEnabled: true,
			PvResizeEnabled:        true,
			GetResourceEnabled:     true,
			ArgocdEnabled:          true,
		},
	}

	registry := registerTasks(cfg, nil, true, cluster_info.Capabilities{})

	k8sTasks := []string{
		"workload_restart", "workload_scale", "pod_evict", "pod_resize",
		"nodeclaim_delete", "pv_resize", "pv_resize_status",
		"get_resource", "list_resources", "list_argocd_applications",
	}
	for _, name := range k8sTasks {
		if _, ok := registry.Get(name); ok {
			t.Errorf("Kubernetes task %q is registered in AWS-only mode (no Kubernetes client) despite its flag being true", name)
		}
	}
}
