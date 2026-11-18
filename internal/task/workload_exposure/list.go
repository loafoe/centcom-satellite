package workload_exposure

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const pageSize = 500

// absent reports an API that isn't installed or isn't readable: optional
// inputs (e.g. Gateway API CRDs) are skipped, not fatal.
func absent(err error) bool {
	return apierrors.IsNotFound(err) || apierrors.IsForbidden(err) || meta.IsNoMatchError(err)
}

// listDynamic lists a Gateway API resource cluster-wide, trying versions in
// order (GA first). installed=false when no version is served.
func (t *Task) listDynamic(ctx context.Context, resource string, versions ...string) (items []unstructured.Unstructured, installed bool, err error) {
	if t.dyn == nil {
		return nil, false, nil
	}
	for _, v := range versions {
		gvr := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: v, Resource: resource}
		var cont string
		items = items[:0]
		for {
			list, err := t.dyn.Resource(gvr).List(ctx, metav1.ListOptions{Limit: pageSize, Continue: cont})
			if err != nil {
				if absent(err) {
					break
				}
				return nil, false, err
			}
			installed = true
			items = append(items, list.Items...)
			if cont = list.GetContinue(); cont == "" {
				return items, true, nil
			}
		}
	}
	return nil, false, nil
}

func (t *Task) listServices(ctx context.Context) ([]corev1.Service, error) {
	var out []corev1.Service
	var cont string
	for {
		l, err := t.cs.CoreV1().Services("").List(ctx, metav1.ListOptions{Limit: pageSize, Continue: cont})
		if err != nil {
			return nil, err
		}
		out = append(out, l.Items...)
		if cont = l.Continue; cont == "" {
			return out, nil
		}
	}
}

func (t *Task) listIngresses(ctx context.Context) ([]networkingv1.Ingress, map[string]string, error) {
	var out []networkingv1.Ingress
	var cont string
	for {
		l, err := t.cs.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{Limit: pageSize, Continue: cont})
		if err != nil {
			if absent(err) {
				return nil, nil, nil
			}
			return nil, nil, err
		}
		out = append(out, l.Items...)
		if cont = l.Continue; cont == "" {
			break
		}
	}
	controllers := map[string]string{} // IngressClass name -> controller
	if cls, err := t.cs.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{}); err == nil {
		for _, c := range cls.Items {
			controllers[c.Name] = c.Spec.Controller
		}
	}
	return out, controllers, nil
}

// lbAddresses returns a Service's (or Ingress's) load balancer addresses.
func lbAddresses(ing []corev1.LoadBalancerIngress) []string {
	var out []string
	for _, i := range ing {
		if i.Hostname != "" {
			out = append(out, i.Hostname)
		} else if i.IP != "" {
			out = append(out, i.IP)
		}
	}
	return out
}
