// Package workload_exposure reports which workloads are reachable from
// outside the cluster, and whether that is the Internet, using only the
// Kubernetes API (no cloud APIs, no extra IAM):
//
//	Gateway (with a LoadBalancer Service / address) <- HTTPRoute/GRPCRoute/TLSRoute
//	Ingress (with a load balancer address)
//	Service type LoadBalancer
//	  -> backend Service -> EndpointSlices -> Pods -> owning workload
//
// A route counts only for parents that accepted it (status.parents). A
// load balancer is "internet" unless the API shows it is internal: scheme
// or internal annotations (AWS/Azure/GKE), the AWS Load Balancer
// Controller's internal default, or only private addresses (see
// lbVerdict). Workload keys are namespace/Kind/name with a Deployment's
// ReplicaSet collapsed, the same keys running_image_vulnerabilities uses.
//
// Performance: cluster-wide lists of Gateways, routes, Ingresses and
// Services; EndpointSlices and pod *metadata* only in namespaces that have
// an exposed backend, with a service-name label selector. The result is
// cached for CacheTTL (one computation at a time), since exposure changes
// far less often than callers ask.
package workload_exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"

	k8sclient "github.com/loafoe/centcom-satellite/internal/k8s"
	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "workload_exposure"

const (
	// CacheTTL bounds how stale a cached result may be.
	CacheTTL = 60 * time.Second
	// TimeBudget bounds one computation.
	TimeBudget = 30 * time.Second
	// maxEntryPoints caps each workload's entry point list.
	maxEntryPoints = 20
)

// Payload for workload_exposure.
type Payload struct {
	// Refresh bypasses the cache.
	Refresh bool `json:"refresh,omitempty"`
}

// EntryPoint is one way traffic reaches a workload from outside.
type EntryPoint struct {
	// Kind: HTTPRoute, GRPCRoute, TLSRoute, Ingress or Service (type LoadBalancer).
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Hostnames []string `json:"hostnames,omitempty"`
	// Via is the Gateway, Ingress class or Service carrying the traffic.
	Via string `json:"via,omitempty"`
	// Address is the load balancer address (hostname or IP).
	Address  string `json:"address,omitempty"`
	Exposure string `json:"exposure"`
	Reason   string `json:"reason"`
	// SourceRanges restrict who may connect (loadBalancerSourceRanges);
	// empty = anyone.
	SourceRanges []string `json:"source_ranges,omitempty"`
}

// Workload is one workload with at least one entry point.
type Workload struct {
	Workload string `json:"workload"`
	// Exposure is the most exposed of its entry points.
	Exposure         string       `json:"exposure"`
	EntryPoints      []EntryPoint `json:"entry_points"`
	EntryPointsTotal int          `json:"entry_points_total"`
}

// Gateway summarizes one Gateway's verdict.
type Gateway struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Class     string `json:"class,omitempty"`
	Address   string `json:"address,omitempty"`
	Exposure  string `json:"exposure"`
	Reason    string `json:"reason"`
}

// Report is the task result.
type Report struct {
	Workloads           []Workload `json:"workloads"`
	InternetWorkloads   int        `json:"internet_workloads"`
	InternalWorkloads   int        `json:"internal_workloads"`
	UnknownWorkloads    int        `json:"unknown_workloads"`
	Gateways            []Gateway  `json:"gateways,omitempty"`
	GatewayAPIInstalled bool       `json:"gateway_api_installed"`
	GeneratedAt         string     `json:"generated_at"`
	DurationMS          int64      `json:"duration_ms"`
	// Cached is true when served from the cache (CacheAgeSeconds old).
	Cached          bool     `json:"cached"`
	CacheAgeSeconds int      `json:"cache_age_seconds,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

// Task implements workload_exposure.
type Task struct {
	cs   kubernetes.Interface
	dyn  dynamic.Interface
	meta metadata.Interface
	now  func() time.Time

	mu       sync.Mutex // one computation at a time; guards the cache
	cached   *Report
	cachedAt time.Time
}

func New(cs kubernetes.Interface, dyn dynamic.Interface, meta metadata.Interface) *Task {
	return &Task{cs: cs, dyn: dyn, meta: meta, now: time.Now}
}

func (t *Task) Name() string { return TaskName }

func (t *Task) Execute(ctx context.Context, raw json.RawMessage) (*task.Result, error) {
	var p Payload
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !p.Refresh && t.cached != nil && t.now().Sub(t.cachedAt) < CacheTTL {
		r := *t.cached
		r.Cached, r.CacheAgeSeconds = true, int(t.now().Sub(t.cachedAt).Seconds())
		return result(&r), nil
	}
	ctx, cancel := context.WithTimeout(ctx, TimeBudget)
	defer cancel()
	start := t.now()
	r, err := t.compute(ctx)
	if err != nil {
		return k8sclient.WrapError("workload exposure", err)
	}
	r.GeneratedAt = start.UTC().Format(time.RFC3339)
	r.DurationMS = t.now().Sub(start).Milliseconds()
	t.cached, t.cachedAt = r, start
	return result(r), nil
}

func result(r *Report) *task.Result {
	return &task.Result{Success: true, Details: *r, Message: fmt.Sprintf(
		"%d workloads reachable from outside the cluster: %d from the Internet, %d internal only, %d unknown",
		len(r.Workloads), r.InternetWorkloads, r.InternalWorkloads, r.UnknownWorkloads)}
}
