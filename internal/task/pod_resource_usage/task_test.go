package pod_resource_usage

import "testing"

func TestRankPods_DefaultPercentSortTiesLimitlessPodsAtZero(t *testing.T) {
	// Reproduces the live "Top Pods by Usage" bug: cilium uses far more
	// CPU/memory than the others but has no declared limits, so its
	// percent-of-limit is 0 — identical to every other limitless pod —
	// and the default percent sort has no way to tell them apart.
	scored := []scoredPod{
		{info: PodUsageInfo{Pod: "cilium", CPUUsage: "78m", MemoryUsage: "386Mi"}, cpuMilli: 78, memBytes: 386 * 1024 * 1024},
		{info: PodUsageInfo{Pod: "external-dns", CPUUsage: "2m", MemoryUsage: "66Mi"}, cpuMilli: 2, memBytes: 66 * 1024 * 1024},
	}
	report := rankPods(scored, Payload{})
	if report.Pods[0].Pod != "cilium" && report.Pods[1].Pod != "cilium" {
		t.Fatalf("expected both present, got %+v", report.Pods)
	}
	// Document the bug: with no limits, percent sort is a tie (both 0),
	// so Go's sort.Slice is not required to prefer cilium - this test
	// exists to contrast with the "usage" sort test below, not to assert
	// a specific tied order.
}

func TestRankPods_UsageSortRanksByAbsoluteCPURegardlessOfLimits(t *testing.T) {
	scored := []scoredPod{
		{info: PodUsageInfo{Pod: "snapshot-controller", CPUUsage: "2m", MemoryUsage: "43Mi"}, cpuMilli: 2, memBytes: 43 * 1024 * 1024},
		{info: PodUsageInfo{Pod: "external-dns", CPUUsage: "2m", MemoryUsage: "66Mi"}, cpuMilli: 2, memBytes: 66 * 1024 * 1024},
		{info: PodUsageInfo{Pod: "cert-manager-webhook", CPUUsage: "1m", MemoryUsage: "31Mi"}, cpuMilli: 1, memBytes: 31 * 1024 * 1024},
		{info: PodUsageInfo{Pod: "cilium", CPUUsage: "78m", MemoryUsage: "386Mi"}, cpuMilli: 78, memBytes: 386 * 1024 * 1024},
		{info: PodUsageInfo{Pod: "cert-manager-cainjector", CPUUsage: "1m", MemoryUsage: "132Mi"}, cpuMilli: 1, memBytes: 132 * 1024 * 1024},
	}
	report := rankPods(scored, Payload{SortBy: "usage"})
	if len(report.Pods) != 5 {
		t.Fatalf("expected 5 pods, got %d", len(report.Pods))
	}
	if report.Pods[0].Pod != "cilium" {
		t.Fatalf("expected cilium (78m CPU, by far the highest) first, got %q", report.Pods[0].Pod)
	}
}

func TestRankPods_UsageSortByMemoryRanksByAbsoluteMemory(t *testing.T) {
	scored := []scoredPod{
		{info: PodUsageInfo{Pod: "small-cpu-big-mem"}, cpuMilli: 1, memBytes: 500 * 1024 * 1024},
		{info: PodUsageInfo{Pod: "big-cpu-small-mem"}, cpuMilli: 1000, memBytes: 10 * 1024 * 1024},
	}
	report := rankPods(scored, Payload{SortBy: "usage", Resource: "memory"})
	if report.Pods[0].Pod != "small-cpu-big-mem" {
		t.Fatalf("expected the higher-memory pod first regardless of CPU, got %q", report.Pods[0].Pod)
	}
}

func TestRankPods_DefaultPercentSortStillPrefersHigherPercentWhenLimitsExist(t *testing.T) {
	// The existing percent-of-limit behavior must be unchanged for pods
	// that DO have limits - "usage" is an addition, not a replacement.
	scored := []scoredPod{
		{info: PodUsageInfo{Pod: "near-limit", CPUPercent: 90, MemoryPercent: 10}, cpuMilli: 90, memBytes: 1},
		{info: PodUsageInfo{Pod: "far-from-limit", CPUPercent: 5, MemoryPercent: 5}, cpuMilli: 5000, memBytes: 999999},
	}
	report := rankPods(scored, Payload{})
	if report.Pods[0].Pod != "near-limit" {
		t.Fatalf("expected percent-of-limit sort (default) to still rank by percent, got %q first", report.Pods[0].Pod)
	}
}

func TestRankPods_LimitAndTruncation(t *testing.T) {
	scored := []scoredPod{
		{info: PodUsageInfo{Pod: "a"}, cpuMilli: 3},
		{info: PodUsageInfo{Pod: "b"}, cpuMilli: 2},
		{info: PodUsageInfo{Pod: "c"}, cpuMilli: 1},
	}
	report := rankPods(scored, Payload{SortBy: "usage", Limit: 2})
	if len(report.Pods) != 2 || !report.Truncated {
		t.Fatalf("expected 2 pods and Truncated=true, got %d pods, truncated=%v", len(report.Pods), report.Truncated)
	}
	if report.Total != 3 {
		t.Fatalf("expected Total to reflect the pre-truncation count (3), got %d", report.Total)
	}
}
