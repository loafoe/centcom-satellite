package workload_exposure

import (
	"context"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (t *Task) compute(ctx context.Context) (*Report, error) {
	var (
		wg                      sync.WaitGroup
		mu                      sync.Mutex
		firstErr                error
		svcs                    []corev1.Service
		ings                    []networkingv1.Ingress
		controllers             map[string]string
		gws                     []unstructured.Unstructured
		routes                  = map[string][]unstructured.Unstructured{}
		gwInstalled, anyRouteOK bool
	)
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	run(func() (err error) { svcs, err = t.listServices(ctx); return })
	run(func() (err error) { ings, controllers, err = t.listIngresses(ctx); return })
	run(func() (err error) { gws, gwInstalled, err = t.listDynamic(ctx, "gateways", "v1", "v1beta1"); return })
	for kind, spec := range map[string][]string{"HTTPRoute": {"httproutes", "v1", "v1beta1"}, "GRPCRoute": {"grpcroutes", "v1", "v1alpha2"}, "TLSRoute": {"tlsroutes", "v1alpha3", "v1alpha2"}} {
		run(func() error {
			items, ok, err := t.listDynamic(ctx, spec[0], spec[1:]...)
			mu.Lock()
			routes[kind], anyRouteOK = items, anyRouteOK || ok
			mu.Unlock()
			return err
		})
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	r := &Report{GatewayAPIInstalled: gwInstalled}
	backends := map[nsName][]EntryPoint{}
	add := func(b nsName, ep EntryPoint) { backends[b] = append(backends[b], ep) }

	gwv := gatewayVerdicts(gws, svcs)
	for _, g := range gwv {
		r.Gateways = append(r.Gateways, g)
	}
	sort.Slice(r.Gateways, func(i, j int) bool {
		return r.Gateways[i].Namespace+"/"+r.Gateways[i].Name < r.Gateways[j].Namespace+"/"+r.Gateways[j].Name
	})
	for _, kind := range []string{"HTTPRoute", "GRPCRoute", "TLSRoute"} {
		routeEntries(kind, routes[kind], gwv, add)
	}
	lbByAddr := map[string]*corev1.Service{}
	for i := range svcs {
		for _, a := range lbAddresses(svcs[i].Status.LoadBalancer.Ingress) {
			lbByAddr[a] = &svcs[i]
		}
	}
	ingressEntries(ings, controllers, lbByAddr, add)
	serviceEntries(svcs, add)
	if !gwInstalled {
		r.Notes = append(r.Notes, "Gateway API is not installed (or not readable): only Ingresses and LoadBalancer Services were considered")
	}

	wls, err := t.backendWorkloads(ctx, backends)
	if err != nil {
		return nil, err
	}
	for wl, eps := range wls {
		eps = dedupe(eps)
		sort.SliceStable(eps, func(i, j int) bool {
			return worse(eps[i].Exposure, eps[j].Exposure) == eps[i].Exposure && eps[i].Exposure != eps[j].Exposure
		})
		w := Workload{Workload: wl, Exposure: Internal, EntryPointsTotal: len(eps)}
		for _, ep := range eps {
			w.Exposure = worse(w.Exposure, ep.Exposure)
		}
		if len(eps) > maxEntryPoints {
			eps = eps[:maxEntryPoints]
		}
		w.EntryPoints = eps
		r.Workloads = append(r.Workloads, w)
		switch w.Exposure {
		case Internet:
			r.InternetWorkloads++
		case Internal:
			r.InternalWorkloads++
		default:
			r.UnknownWorkloads++
		}
	}
	sort.Slice(r.Workloads, func(i, j int) bool { return r.Workloads[i].Workload < r.Workloads[j].Workload })
	return r, nil
}

func dedupe(eps []EntryPoint) []EntryPoint {
	seen := map[string]bool{}
	out := eps[:0:0]
	for _, ep := range eps {
		k := ep.Kind + "|" + ep.Namespace + "|" + ep.Name + "|" + ep.Via
		if !seen[k] {
			seen[k] = true
			out = append(out, ep)
		}
	}
	return out
}

var podGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

// backendWorkloads maps backend Services to the workloads behind them:
// their EndpointSlices' target pods (where traffic actually lands, so a
// selector matching several workloads counts them all), each pod named by
// its owning workload. Only namespaces with a backend are read; pods as
// metadata only.
func (t *Task) backendWorkloads(ctx context.Context, backends map[nsName][]EntryPoint) (map[string][]EntryPoint, error) {
	byNS := map[string][]string{}
	for b := range backends {
		byNS[b.ns] = append(byNS[b.ns], b.name)
	}
	out := map[string][]EntryPoint{}
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for ns, names := range byNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := t.namespaceWorkloads(ctx, ns, names, backends)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for wl, eps := range res {
				out[wl] = append(out[wl], eps...)
			}
		}()
	}
	wg.Wait()
	return out, firstErr
}

func (t *Task) namespaceWorkloads(ctx context.Context, ns string, names []string, backends map[nsName][]EntryPoint) (map[string][]EntryPoint, error) {
	podSvcs := map[string][]string{} // pod -> backend services
	sort.Strings(names)
	for start := 0; start < len(names); start += 50 {
		chunk := names[start:min(start+50, len(names))]
		sel := "kubernetes.io/service-name in (" + strings.Join(chunk, ",") + ")"
		var cont string
		for {
			l, err := t.cs.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{LabelSelector: sel, Limit: pageSize, Continue: cont})
			if err != nil {
				if absent(err) {
					return nil, nil
				}
				return nil, err
			}
			for _, es := range l.Items {
				svc := es.Labels["kubernetes.io/service-name"]
				for _, ep := range es.Endpoints {
					if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
						podSvcs[ep.TargetRef.Name] = append(podSvcs[ep.TargetRef.Name], svc)
					}
				}
			}
			if cont = l.Continue; cont == "" {
				break
			}
		}
	}
	if len(podSvcs) == 0 {
		return nil, nil
	}
	out := map[string][]EntryPoint{}
	var cont string
	for {
		l, err := t.meta.Resource(podGVR).Namespace(ns).List(ctx, metav1.ListOptions{Limit: pageSize, Continue: cont})
		if err != nil {
			return nil, err
		}
		for _, p := range l.Items {
			svcs, ok := podSvcs[p.Name]
			if !ok {
				continue
			}
			wl := workloadOf(p.ObjectMeta)
			for _, s := range svcs {
				out[wl] = append(out[wl], backends[nsName{ns, s}]...)
			}
		}
		if cont = l.Continue; cont == "" {
			return out, nil
		}
	}
}

// workloadOf names a pod's workload as namespace/Kind/name, collapsing a
// Deployment's ReplicaSet to the Deployment: the same keys
// running_image_vulnerabilities uses, so callers can join the two.
func workloadOf(m metav1.ObjectMeta) string {
	for _, o := range m.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		kind, name := o.Kind, o.Name
		if kind == "ReplicaSet" {
			if h := m.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(name, "-"+h) {
				kind, name = "Deployment", strings.TrimSuffix(name, "-"+h)
			}
		}
		return m.Namespace + "/" + kind + "/" + name
	}
	return m.Namespace + "/Pod/" + m.Name
}
