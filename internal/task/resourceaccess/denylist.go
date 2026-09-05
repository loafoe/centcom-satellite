// Package resourceaccess provides a shared, config-driven GVK denylist for
// generic resource-reading tasks (get_resource today; any future
// list-style equivalent should consult the same Denylist so the exclusion
// cannot be bypassed by listing instead of getting).
package resourceaccess

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// DefaultDenied is always excluded, even with empty configuration — Secrets
// are the non-negotiable floor. The `view` ClusterRole binding (see the
// centcom-satellite Helm chart) already blocks Secret reads at the RBAC
// layer when get_resource is enabled; this is defense in depth on top of
// that, not instead of it.
var DefaultDenied = []schema.GroupKind{
	{Group: "", Kind: "Secret"},
}

// Denylist blocks specific group+kind pairs from the generic resource
// readers. An empty Group matches the core ("") group. Kind and Group match
// case-insensitively.
type Denylist struct {
	denied map[schema.GroupKind]struct{}
}

// New builds a Denylist containing DefaultDenied plus extra. extra is
// typically the operator-configured list (RESOURCE_ACCESS_DENY); nil or
// empty is fine — DefaultDenied still applies.
func New(extra []schema.GroupKind) *Denylist {
	d := &Denylist{denied: make(map[schema.GroupKind]struct{}, len(DefaultDenied)+len(extra))}
	for _, gk := range DefaultDenied {
		d.denied[normalize(gk)] = struct{}{}
	}
	for _, gk := range extra {
		d.denied[normalize(gk)] = struct{}{}
	}
	return d
}

// IsDenied reports whether gk is blocked.
func (d *Denylist) IsDenied(gk schema.GroupKind) bool {
	_, ok := d.denied[normalize(gk)]
	return ok
}

func normalize(gk schema.GroupKind) schema.GroupKind {
	return schema.GroupKind{Group: strings.ToLower(gk.Group), Kind: strings.ToLower(gk.Kind)}
}

// ParseGroupKindList parses a comma-separated "group/Kind" list, e.g.
// "cert-manager.io/Certificate,/ServiceAccount,external-secrets.io/SecretStore".
// An empty group before the slash denotes the core API group (kind alone,
// e.g. "/ServiceAccount", not "ServiceAccount" - the slash is required so a
// bare kind is never silently misread as a group). Empty input returns a
// nil slice, nil error.
func ParseGroupKindList(s string) ([]schema.GroupKind, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	var result []schema.GroupKind
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.LastIndex(entry, "/")
		if idx < 0 {
			return nil, fmt.Errorf("invalid entry %q: expected group/Kind (empty group for core, e.g. /ServiceAccount)", entry)
		}
		group := entry[:idx]
		kind := entry[idx+1:]
		if kind == "" {
			return nil, fmt.Errorf("invalid entry %q: kind is required after the slash", entry)
		}
		result = append(result, schema.GroupKind{Group: group, Kind: kind})
	}
	return result, nil
}
