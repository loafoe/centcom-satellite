package workload_exposure

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type nsName struct{ ns, name string }

// gatewayVerdicts classifies every Gateway by its own LoadBalancer Service
// (owned by the Gateway, or labelled gateway.networking.k8s.io/gateway-name
// as Cilium, Istio and Envoy Gateway do), falling back to the Gateway's
// status addresses and infrastructure annotations.
func gatewayVerdicts(gws []unstructured.Unstructured, svcs []corev1.Service) map[nsName]Gateway {
	owned := map[nsName]*corev1.Service{}
	for i := range svcs {
		s := &svcs[i]
		for _, o := range s.OwnerReferences {
			if o.Kind == "Gateway" {
				owned[nsName{s.Namespace, o.Name}] = s
			}
		}
		for _, l := range []string{"gateway.networking.k8s.io/gateway-name", "gateway.envoyproxy.io/owning-gateway-name"} {
			if gw := s.Labels[l]; gw != "" {
				if _, ok := owned[nsName{s.Namespace, gw}]; !ok {
					owned[nsName{s.Namespace, gw}] = s
				}
			}
		}
	}
	out := map[nsName]Gateway{}
	for _, gw := range gws {
		k := nsName{gw.GetNamespace(), gw.GetName()}
		class, _, _ := unstructured.NestedString(gw.Object, "spec", "gatewayClassName")
		g := Gateway{Namespace: k.ns, Name: k.name, Class: class}
		if s := owned[k]; s != nil {
			switch s.Spec.Type {
			case corev1.ServiceTypeLoadBalancer:
				addrs := lbAddresses(s.Status.LoadBalancer.Ingress)
				g.Exposure, g.Reason = lbVerdict(s.Annotations, ptrString(s.Spec.LoadBalancerClass), addrs)
				g.Reason = "LoadBalancer Service " + s.Namespace + "/" + s.Name + ": " + g.Reason
				if len(addrs) > 0 {
					g.Address = addrs[0]
				}
			case corev1.ServiceTypeNodePort:
				g.Exposure, g.Reason = Unknown, "NodePort Service "+s.Name+": reachable only if the nodes are"
			default:
				g.Exposure, g.Reason = Internal, string(s.Spec.Type)+" Service "+s.Name+" (no load balancer)"
			}
			out[k] = g
			continue
		}
		var addrs []string
		list, _, _ := unstructured.NestedSlice(gw.Object, "status", "addresses")
		for _, a := range list {
			if m, ok := a.(map[string]any); ok {
				if v, _ := m["value"].(string); v != "" {
					addrs = append(addrs, v)
				}
			}
		}
		ann, _, _ := unstructured.NestedStringMap(gw.Object, "spec", "infrastructure", "annotations")
		g.Exposure, g.Reason = lbVerdict(ann, "", addrs)
		g.Reason = "Gateway address: " + g.Reason
		if len(addrs) > 0 {
			g.Address = addrs[0]
		}
		out[k] = g
	}
	return out
}

// routeEntries adds one entry point per (route, accepted Gateway parent,
// backend Service).
func routeEntries(kind string, routes []unstructured.Unstructured, gws map[nsName]Gateway, add func(backend nsName, ep EntryPoint)) {
	for _, r := range routes {
		ns := r.GetNamespace()
		hosts, _, _ := unstructured.NestedStringSlice(r.Object, "spec", "hostnames")
		accepted := acceptedParents(r)
		parents, _, _ := unstructured.NestedSlice(r.Object, "spec", "parentRefs")
		var gwsHere []Gateway
		for _, p := range parents {
			m, _ := p.(map[string]any)
			if k, _ := m["kind"].(string); k != "" && k != "Gateway" {
				continue // e.g. a mesh (GAMMA) Service parent: not an entry point
			}
			pk := nsName{ns, str(m["name"])}
			if v := str(m["namespace"]); v != "" {
				pk.ns = v
			}
			if ok, known := accepted[pk]; known && !ok {
				continue
			}
			if g, ok := gws[pk]; ok {
				gwsHere = append(gwsHere, g)
			}
		}
		if len(gwsHere) == 0 {
			continue
		}
		rules, _, _ := unstructured.NestedSlice(r.Object, "spec", "rules")
		for _, rule := range rules {
			rm, _ := rule.(map[string]any)
			refs, _ := rm["backendRefs"].([]any)
			for _, b := range refs {
				bm, _ := b.(map[string]any)
				if k := str(bm["kind"]); k != "" && k != "Service" {
					continue
				}
				bk := nsName{ns, str(bm["name"])}
				if v := str(bm["namespace"]); v != "" {
					bk.ns = v
				}
				for _, g := range gwsHere {
					add(bk, EntryPoint{Kind: kind, Namespace: ns, Name: r.GetName(), Hostnames: hosts,
						Via: "Gateway " + g.Namespace + "/" + g.Name, Address: g.Address, Exposure: g.Exposure, Reason: g.Reason})
				}
			}
		}
	}
}

// acceptedParents reads status.parents: parent -> Accepted condition true.
// A parent missing from the status is unknown (not reported), not rejected.
func acceptedParents(r unstructured.Unstructured) map[nsName]bool {
	out := map[nsName]bool{}
	list, _, _ := unstructured.NestedSlice(r.Object, "status", "parents")
	for _, p := range list {
		m, _ := p.(map[string]any)
		ref, _ := m["parentRef"].(map[string]any)
		k := nsName{r.GetNamespace(), str(ref["name"])}
		if v := str(ref["namespace"]); v != "" {
			k.ns = v
		}
		conds, _ := m["conditions"].([]any)
		ok := false
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			if str(cm["type"]) == "Accepted" && str(cm["status"]) == "True" {
				ok = true
			}
		}
		out[k] = out[k] || ok
	}
	return out
}

// ingressEntries: Ingresses with a load balancer address, classified by
// the ALB scheme annotation, else the ingress controller's own LoadBalancer
// Service (matched by address, e.g. ingress-nginx), else the address.
func ingressEntries(ings []networkingv1.Ingress, controllers map[string]string, lbByAddr map[string]*corev1.Service, add func(backend nsName, ep EntryPoint)) {
	for _, ing := range ings {
		addrs := lbAddresses(ingressLB(ing.Status.LoadBalancer.Ingress))
		if len(addrs) == 0 {
			continue // no load balancer: not reachable from outside
		}
		class := ptrString(ing.Spec.IngressClassName)
		if class == "" {
			class = ing.Annotations["kubernetes.io/ingress.class"]
		}
		ep := EntryPoint{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name, Address: addrs[0], Via: "IngressClass " + class}
		switch scheme := strings.ToLower(ing.Annotations["alb.ingress.kubernetes.io/scheme"]); {
		case scheme == "internal":
			ep.Exposure, ep.Reason = Internal, "ALB scheme: internal"
		case scheme == "internet-facing":
			ep.Exposure, ep.Reason = Internet, "ALB scheme: internet-facing"
		case lbByAddr[addrs[0]] != nil:
			s := lbByAddr[addrs[0]]
			e, why := lbVerdict(s.Annotations, ptrString(s.Spec.LoadBalancerClass), addrs)
			ep.Exposure, ep.Reason, ep.SourceRanges = e, "ingress controller Service "+s.Namespace+"/"+s.Name+": "+why, s.Spec.LoadBalancerSourceRanges
		case controllers[class] == "ingress.k8s.aws/alb" || class == "alb":
			ep.Exposure, ep.Reason = Internal, "AWS Load Balancer Controller ALB without a scheme annotation (defaults to internal)"
		default:
			ep.Exposure, ep.Reason = addressVerdict(addrs)
		}
		for _, h := range ing.Spec.Rules {
			if h.Host != "" {
				ep.Hostnames = append(ep.Hostnames, h.Host)
			}
		}
		if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
			add(nsName{ing.Namespace, b.Service.Name}, ep)
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				if p.Backend.Service != nil {
					add(nsName{ing.Namespace, p.Backend.Service.Name}, ep)
				}
			}
		}
	}
}

func ingressLB(in []networkingv1.IngressLoadBalancerIngress) []corev1.LoadBalancerIngress {
	out := make([]corev1.LoadBalancerIngress, 0, len(in))
	for _, i := range in {
		out = append(out, corev1.LoadBalancerIngress{Hostname: i.Hostname, IP: i.IP})
	}
	return out
}

// serviceEntries: Services of type LoadBalancer not owned by a Gateway
// (those are covered through their routes).
func serviceEntries(svcs []corev1.Service, add func(backend nsName, ep EntryPoint)) {
	for _, s := range svcs {
		if s.Spec.Type != corev1.ServiceTypeLoadBalancer || ownedByGateway(&s) {
			continue
		}
		addrs := lbAddresses(s.Status.LoadBalancer.Ingress)
		e, why := lbVerdict(s.Annotations, ptrString(s.Spec.LoadBalancerClass), addrs)
		ep := EntryPoint{Kind: "Service", Namespace: s.Namespace, Name: s.Name, Via: "LoadBalancer Service", Exposure: e, Reason: why, SourceRanges: s.Spec.LoadBalancerSourceRanges}
		if len(addrs) > 0 {
			ep.Address = addrs[0]
		}
		add(nsName{s.Namespace, s.Name}, ep)
	}
}

func ownedByGateway(s *corev1.Service) bool {
	for _, o := range s.OwnerReferences {
		if o.Kind == "Gateway" {
			return true
		}
	}
	return s.Labels["gateway.networking.k8s.io/gateway-name"] != ""
}

func str(v any) string { s, _ := v.(string); return s }

func ptrString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
