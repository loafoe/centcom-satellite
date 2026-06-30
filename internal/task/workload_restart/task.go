// Package workload_restart provides workload restart functionality.
package workload_restart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const (
	TaskName           = "workload_restart"
	NoRestartAnnotation = "picoclaw.io/no-restart"
	RestartedAtAnnotation = "kubectl.kubernetes.io/restartedAt"
)

var (
	ErrInvalidPayload     = errors.New("invalid payload")
	ErrMissingNamespace   = errors.New("namespace is required")
	ErrMissingName        = errors.New("name is required")
	ErrMissingKind        = errors.New("kind is required")
	ErrInvalidKind        = errors.New("kind must be deployment, statefulset, or daemonset")
	ErrRestartNotAllowed  = errors.New("restart not allowed by annotation")
	ErrWorkloadNotFound   = errors.New("workload not found")
	ErrPDBBlocked         = errors.New("restart blocked by PodDisruptionBudget with disruptionsAllowed=0")
)

// Payload represents the input for a workload restart operation.
type Payload struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	DryRun    bool   `json:"dry_run"`
}

// RestartDetails contains additional information about the restart operation.
type RestartDetails struct {
	DryRun          bool   `json:"dry_run,omitempty"`
	PreviousRestart string `json:"previous_restart,omitempty"`
	Replicas        int32  `json:"replicas"`
	Message         string `json:"message,omitempty"`
}

// Task handles workload restart operations.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new workload restart task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs the workload restart operation.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	payload, err := t.parsePayload(rawPayload)
	if err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	if err := t.validatePayload(payload); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Check namespace annotation for no-restart
	ns, err := t.clientset.CoreV1().Namespaces().Get(ctx, payload.Namespace, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("namespace not found: %s", payload.Namespace)), nil
		}
		return nil, fmt.Errorf("failed to get namespace: %w", err)
	}

	if ns.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("%s: namespace %s has %s=true", ErrRestartNotAllowed, payload.Namespace, NoRestartAnnotation)), nil
	}

	// Execute restart based on kind
	switch payload.Kind {
	case "deployment":
		return t.restartDeployment(ctx, payload)
	case "statefulset":
		return t.restartStatefulSet(ctx, payload)
	case "daemonset":
		return t.restartDaemonSet(ctx, payload)
	default:
		return task.NewErrorResult(fmt.Sprintf("%s: %s", ErrInvalidKind, payload.Kind)), nil
	}
}

func (t *Task) parsePayload(rawPayload json.RawMessage) (*Payload, error) {
	if len(rawPayload) == 0 {
		return nil, ErrInvalidPayload
	}

	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return &payload, nil
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Namespace == "" {
		return ErrMissingNamespace
	}
	if p.Name == "" {
		return ErrMissingName
	}
	if p.Kind == "" {
		return ErrMissingKind
	}

	// Validate kind
	switch p.Kind {
	case "deployment", "statefulset", "daemonset":
		// valid
	default:
		return ErrInvalidKind
	}

	return nil
}

func (t *Task) restartDeployment(ctx context.Context, payload *Payload) (*task.Result, error) {
	deployment, err := t.clientset.AppsV1().Deployments(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("%s: deployment %s/%s", ErrWorkloadNotFound, payload.Namespace, payload.Name)), nil
		}
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Check workload annotation for no-restart
	if deployment.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("%s: deployment %s/%s has %s=true", ErrRestartNotAllowed, payload.Namespace, payload.Name, NoRestartAnnotation)), nil
	}

	// Check PDB
	if err := t.checkPDB(ctx, payload.Namespace, deployment.Spec.Selector); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Extract previous restart time
	previousRestart := deployment.Spec.Template.Annotations[RestartedAtAnnotation]

	var replicas int32 = 1
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}

	// Handle dry-run mode
	if payload.DryRun {
		details := RestartDetails{
			DryRun:          true,
			PreviousRestart: previousRestart,
			Replicas:        replicas,
			Message:         "Would trigger rolling restart by updating restartedAt annotation",
		}
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would restart deployment %s/%s (%d replicas)", payload.Namespace, payload.Name, replicas),
			details,
		), nil
	}

	// Perform restart by patching the restartedAt annotation
	now := time.Now().Format(time.RFC3339)
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"%s":"%s"}}}}}`, RestartedAtAnnotation, now)

	_, err = t.clientset.AppsV1().Deployments(payload.Namespace).Patch(
		ctx,
		payload.Name,
		types.StrategicMergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to patch deployment: %w", err)
	}

	slog.Info("deployment restarted",
		"namespace", payload.Namespace,
		"name", payload.Name,
		"replicas", replicas,
		"previous_restart", previousRestart,
	)

	details := RestartDetails{
		PreviousRestart: previousRestart,
		Replicas:        replicas,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Deployment %s/%s restart triggered (%d replicas)", payload.Namespace, payload.Name, replicas),
		details,
	), nil
}

func (t *Task) restartStatefulSet(ctx context.Context, payload *Payload) (*task.Result, error) {
	statefulset, err := t.clientset.AppsV1().StatefulSets(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("%s: statefulset %s/%s", ErrWorkloadNotFound, payload.Namespace, payload.Name)), nil
		}
		return nil, fmt.Errorf("failed to get statefulset: %w", err)
	}

	// Check workload annotation for no-restart
	if statefulset.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("%s: statefulset %s/%s has %s=true", ErrRestartNotAllowed, payload.Namespace, payload.Name, NoRestartAnnotation)), nil
	}

	// Check PDB
	if err := t.checkPDB(ctx, payload.Namespace, statefulset.Spec.Selector); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Extract previous restart time
	previousRestart := statefulset.Spec.Template.Annotations[RestartedAtAnnotation]

	var replicas int32 = 1
	if statefulset.Spec.Replicas != nil {
		replicas = *statefulset.Spec.Replicas
	}

	// Handle dry-run mode
	if payload.DryRun {
		details := RestartDetails{
			DryRun:          true,
			PreviousRestart: previousRestart,
			Replicas:        replicas,
			Message:         "Would trigger rolling restart by updating restartedAt annotation",
		}
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would restart statefulset %s/%s (%d replicas)", payload.Namespace, payload.Name, replicas),
			details,
		), nil
	}

	// Perform restart by patching the restartedAt annotation
	now := time.Now().Format(time.RFC3339)
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"%s":"%s"}}}}}`, RestartedAtAnnotation, now)

	_, err = t.clientset.AppsV1().StatefulSets(payload.Namespace).Patch(
		ctx,
		payload.Name,
		types.StrategicMergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to patch statefulset: %w", err)
	}

	slog.Info("statefulset restarted",
		"namespace", payload.Namespace,
		"name", payload.Name,
		"replicas", replicas,
		"previous_restart", previousRestart,
	)

	details := RestartDetails{
		PreviousRestart: previousRestart,
		Replicas:        replicas,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("StatefulSet %s/%s restart triggered (%d replicas)", payload.Namespace, payload.Name, replicas),
		details,
	), nil
}

func (t *Task) restartDaemonSet(ctx context.Context, payload *Payload) (*task.Result, error) {
	daemonset, err := t.clientset.AppsV1().DaemonSets(payload.Namespace).Get(ctx, payload.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("%s: daemonset %s/%s", ErrWorkloadNotFound, payload.Namespace, payload.Name)), nil
		}
		return nil, fmt.Errorf("failed to get daemonset: %w", err)
	}

	// Check workload annotation for no-restart
	if daemonset.Annotations[NoRestartAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("%s: daemonset %s/%s has %s=true", ErrRestartNotAllowed, payload.Namespace, payload.Name, NoRestartAnnotation)), nil
	}

	// DaemonSets don't typically have PDBs, but we'll check anyway
	// Note: We skip PDB check for DaemonSets as they manage node-level workloads

	// Extract previous restart time
	previousRestart := daemonset.Spec.Template.Annotations[RestartedAtAnnotation]

	replicas := daemonset.Status.DesiredNumberScheduled

	// Handle dry-run mode
	if payload.DryRun {
		details := RestartDetails{
			DryRun:          true,
			PreviousRestart: previousRestart,
			Replicas:        replicas,
			Message:         "Would trigger rolling restart by updating restartedAt annotation",
		}
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would restart daemonset %s/%s (%d desired pods)", payload.Namespace, payload.Name, replicas),
			details,
		), nil
	}

	// Perform restart by patching the restartedAt annotation
	now := time.Now().Format(time.RFC3339)
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"%s":"%s"}}}}}`, RestartedAtAnnotation, now)

	_, err = t.clientset.AppsV1().DaemonSets(payload.Namespace).Patch(
		ctx,
		payload.Name,
		types.StrategicMergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to patch daemonset: %w", err)
	}

	slog.Info("daemonset restarted",
		"namespace", payload.Namespace,
		"name", payload.Name,
		"desired_pods", replicas,
		"previous_restart", previousRestart,
	)

	details := RestartDetails{
		PreviousRestart: previousRestart,
		Replicas:        replicas,
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("DaemonSet %s/%s restart triggered (%d desired pods)", payload.Namespace, payload.Name, replicas),
		details,
	), nil
}

// checkPDB checks if any PodDisruptionBudget would block the restart.
func (t *Task) checkPDB(ctx context.Context, namespace string, selector *metav1.LabelSelector) error {
	pdbs, err := t.clientset.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list PDBs: %w", err)
	}

	if selector == nil || len(selector.MatchLabels) == 0 {
		// No selector, cannot check PDB matching
		return nil
	}

	for _, pdb := range pdbs.Items {
		if t.pdbMatchesSelector(&pdb, selector) {
			if pdb.Status.DisruptionsAllowed == 0 {
				return fmt.Errorf("%w: PDB %s/%s", ErrPDBBlocked, namespace, pdb.Name)
			}
		}
	}

	return nil
}

// pdbMatchesSelector checks if a PDB selector matches the workload selector.
func (t *Task) pdbMatchesSelector(pdb *policyv1.PodDisruptionBudget, selector *metav1.LabelSelector) bool {
	if pdb.Spec.Selector == nil || len(pdb.Spec.Selector.MatchLabels) == 0 {
		return false
	}

	// Simple label matching: check if all PDB selector labels are present in workload selector
	for key, value := range pdb.Spec.Selector.MatchLabels {
		if selector.MatchLabels[key] != value {
			return false
		}
	}

	return true
}
