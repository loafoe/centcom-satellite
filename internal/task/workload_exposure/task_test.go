package workload_exposure

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
)

func lbService(ns, name, gateway, scheme, host string) *corev1.Service {
	s := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": scheme}},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
		Status:     corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{Hostname: host}}}},
	}
	if gateway != "" {
		s.OwnerReferences = []metav1.OwnerReference{{Kind: "Gateway", Name: gateway}}
	}
	return s
}

func backendService(ns, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP}}
}

func slice(ns, svc string, pods ...string) *discoveryv1.EndpointSlice {
	es := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: svc + "-x", Labels: map[string]string{"kubernetes.io/service-name": svc}}}
	for _, p := range pods {
		es.Endpoints = append(es.Endpoints, discoveryv1.Endpoint{TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: p}})
	}
	return es
}

func podMeta(ns, name, ownerKind, owner string, labels map[string]string) *metav1.PartialObjectMetadata {
	ctrl := true
	return &metav1.PartialObjectMetadata{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels, OwnerReferences: []metav1.OwnerReference{{Kind: ownerKind, Name: owner, Controller: &ctrl}}},
	}
}

func gateway(ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]any{"namespace": ns, "name": name}, "spec": map[string]any{"gatewayClassName": "cilium"},
	}}
}

func route(ns, name, parentNS, parent, backend string, accepted bool) *unstructured.Unstructured {
	status := "True"
	if !accepted {
		status = "False"
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"hostnames":  []any{name + ".example.com"},
			"parentRefs": []any{map[string]any{"name": parent, "namespace": parentNS}},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": backend, "port": int64(80)}}}},
		},
		"status": map[string]any{"parents": []any{map[string]any{
			"parentRef":  map[string]any{"name": parent, "namespace": parentNS},
			"conditions": []any{map[string]any{"type": "Accepted", "status": status}},
		}}},
	}}
}

func newFakeTask(t *testing.T) *Task {
	t.Helper()
	cs := fake.NewSimpleClientset(
		lbService("kube-system", "cilium-gateway-platform", "platform", "internet-facing", "pub.elb.amazonaws.com"),
		lbService("kube-system", "cilium-gateway-private", "private", "internal", "internal-x.elb.amazonaws.com"),
		backendService("shop", "web"), backendService("shop", "admin"), backendService("shop", "secret"), backendService("shop", "worker"),
		slice("shop", "web", "web-abc12-x", "web-abc12-y"), slice("shop", "admin", "admin-0"), slice("shop", "secret", "secret-0"), slice("shop", "worker", "worker-0"),
	)
	scheme := runtime.NewScheme()
	gvrs := map[schema.GroupVersionResource]string{
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}:   "GatewayList",
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}: "HTTPRouteList",
		// Served but empty (the fake panics on unregistered resources,
		// where a real API server answers NotFound).
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}:      "GRPCRouteList",
		{Group: "gateway.networking.k8s.io", Version: "v1alpha3", Resource: "tlsroutes"}: "TLSRouteList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrs)
	gwGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	rtGVR := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	for _, o := range []struct {
		gvr schema.GroupVersionResource
		obj *unstructured.Unstructured
	}{
		{gwGVR, gateway("kube-system", "platform")}, {gwGVR, gateway("kube-system", "private")},
		{rtGVR, route("shop", "web", "kube-system", "platform", "web", true)},
		{rtGVR, route("shop", "admin", "kube-system", "private", "admin", true)},
		{rtGVR, route("shop", "secret", "kube-system", "platform", "secret", false)}, // the Gateway rejected it
	} {
		if _, err := dyn.Resource(o.gvr).Namespace(o.obj.GetNamespace()).Create(context.Background(), o.obj, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ms := metadatafake.NewTestScheme()
	metav1.AddMetaToScheme(ms)
	meta := metadatafake.NewSimpleMetadataClient(ms,
		podMeta("shop", "web-abc12-x", "ReplicaSet", "web-abc12", map[string]string{"pod-template-hash": "abc12"}),
		podMeta("shop", "web-abc12-y", "ReplicaSet", "web-abc12", map[string]string{"pod-template-hash": "abc12"}),
		podMeta("shop", "admin-0", "StatefulSet", "admin", nil),
		podMeta("shop", "secret-0", "StatefulSet", "secret", nil),
		podMeta("shop", "worker-0", "StatefulSet", "worker", nil), // no route at all
	)
	return New(cs, dyn, meta)
}

func runTask(t *testing.T, tk *Task, payload string) Report {
	t.Helper()
	res, err := tk.Execute(context.Background(), json.RawMessage(payload))
	if err != nil || !res.Success {
		t.Fatalf("execute: %v %+v", err, res)
	}
	return res.Details.(Report)
}

func TestExecute_RoutesThroughLoadBalancerGateways(t *testing.T) {
	tk := newFakeTask(t)
	r := runTask(t, tk, `{}`)
	got := map[string]Workload{}
	for _, w := range r.Workloads {
		got[w.Workload] = w
	}
	if w := got["shop/Deployment/web"]; w.Exposure != Internet || len(w.EntryPoints) != 1 || w.EntryPoints[0].Via != "Gateway kube-system/platform" || w.EntryPoints[0].Hostnames[0] != "web.example.com" {
		t.Fatalf("web (both pods, one Deployment): %+v", w)
	}
	if w := got["shop/StatefulSet/admin"]; w.Exposure != Internal {
		t.Fatalf("admin behind the internal Gateway: %+v", w)
	}
	if _, ok := got["shop/StatefulSet/secret"]; ok {
		t.Fatal("a route the Gateway rejected must not expose its backend")
	}
	if _, ok := got["shop/StatefulSet/worker"]; ok {
		t.Fatal("a workload without any route must not be listed")
	}
	if r.InternetWorkloads != 1 || r.InternalWorkloads != 1 || !r.GatewayAPIInstalled || len(r.Gateways) != 2 {
		t.Fatalf("report: %+v", r)
	}
}

func TestExecute_CachesAndRefreshes(t *testing.T) {
	tk := newFakeTask(t)
	clock := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	tk.now = func() time.Time { return clock }
	if r := runTask(t, tk, `{}`); r.Cached {
		t.Fatal("first call computed")
	}
	clock = clock.Add(30 * time.Second)
	if r := runTask(t, tk, `{}`); !r.Cached || r.CacheAgeSeconds != 30 {
		t.Fatalf("within CacheTTL: %+v", r)
	}
	if r := runTask(t, tk, `{"refresh":true}`); r.Cached {
		t.Fatal("refresh bypasses the cache")
	}
	clock = clock.Add(CacheTTL + time.Second)
	if r := runTask(t, tk, `{}`); r.Cached {
		t.Fatal("expired cache recomputes")
	}
}
