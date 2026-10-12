// Package list_pdbs provides PodDisruptionBudget listing functionality.
package list_pdbs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_pdbs"

// Payload for list_pdbs task.
type Payload struct {
	Namespace string `json:"namespace"` // required, or empty for all
}

// PDBList contains the PodDisruptionBudget listing.
type PDBList struct {
	Total int       `json:"total"`
	PDBs  []PDBInfo `json:"pdbs"`
}

// PDBInfo contains PodDisruptionBudget details.
type PDBInfo struct {
	Name               string            `json:"name"`
	Namespace          string            `json:"namespace"`
	Selector           map[string]string `json:"selector,omitempty"`
	MinAvailable       string            `json:"min_available,omitempty"`
	MaxUnavailable     string            `json:"max_unavailable,omitempty"`
	CurrentHealthy     int32             `json:"current_healthy"`
	DesiredHealthy     int32             `json:"desired_healthy"`
	DisruptionsAllowed int32             `json:"disruptions_allowed"`
	ExpectedPods       int32             `json:"expected_pods"`
	Age                string            `json:"age"`
}

// Task handles PDB listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list PDBs task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists PodDisruptionBudgets in a namespace (or all namespaces).
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	pdbs, err := t.clientset.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list PodDisruptionBudgets: %w", err)
	}

	infos := make([]PDBInfo, 0, len(pdbs.Items))
	for i := range pdbs.Items {
		infos = append(infos, buildPDBInfo(&pdbs.Items[i]))
	}

	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Namespace != infos[j].Namespace {
			return infos[i].Namespace < infos[j].Namespace
		}
		return infos[i].Name < infos[j].Name
	})

	result := &PDBList{Total: len(infos), PDBs: infos}

	msg := fmt.Sprintf("Found %d PodDisruptionBudgets in namespace %s", result.Total, namespace)
	if namespace == metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d PodDisruptionBudgets across all namespaces", result.Total)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func buildPDBInfo(pdb *policyv1.PodDisruptionBudget) PDBInfo {
	info := PDBInfo{
		Name:               pdb.Name,
		Namespace:          pdb.Namespace,
		CurrentHealthy:     pdb.Status.CurrentHealthy,
		DesiredHealthy:     pdb.Status.DesiredHealthy,
		DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
		ExpectedPods:       pdb.Status.ExpectedPods,
		Age:                formatAge(pdb.CreationTimestamp.Time),
	}
	if pdb.Spec.Selector != nil {
		info.Selector = pdb.Spec.Selector.MatchLabels
	}
	if pdb.Spec.MinAvailable != nil {
		info.MinAvailable = pdb.Spec.MinAvailable.String()
	}
	if pdb.Spec.MaxUnavailable != nil {
		info.MaxUnavailable = pdb.Spec.MaxUnavailable.String()
	}
	return info
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
