package helm_application

import "fmt"

// ConflictError indicates an update was rejected because the caller's
// ResourceVersion no longer matches the object's current one - the object
// was modified (by this task or anything else) since the caller last read
// it. Distinguishable via errors.As so callers can render a specific
// "re-fetch and retry" message rather than a generic failure.
type ConflictError struct{ Name string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("HelmApplication %q was modified since it was last read; re-fetch and retry", e.Name)
}

// StuckDeletingError indicates a delete was accepted by the API server but
// the object still carries finalizers after the check - most likely the
// forbidden ArgoCD resources-finalizer manually added despite the
// documented guardrail against it.
type StuckDeletingError struct {
	Name       string
	Finalizers []string
}

func (e *StuckDeletingError) Error() string {
	return fmt.Sprintf("HelmApplication %q is stuck deleting (finalizers: %v) — see the anti-finalizer guardrail in crossplane-compositions/kustomize/base/helmapp/README.md", e.Name, e.Finalizers)
}
