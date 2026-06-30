package workload_scale

import (
	"context"
	"encoding/json"
	"fmt"

	autoscalingv1 "k8s.io/api/autoscaling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const (
	TaskName          = "workload_scale"
	NoScaleAnnotation = "picoclaw.io/no-scale"
)

type Payload struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Replicas         int32  `json:"replicas"`
	AllowScaleToZero bool   `json:"allow_scale_to_zero"`
	DryRun           bool   `json:"dry_run"`
}

type ScaleDetails struct {
	DryRun           bool   `json:"dry_run,omitempty"`
	PreviousReplicas int32  `json:"previous_replicas"`
	NewReplicas      int32  `json:"new_replicas"`
	HPAWarning       string `json:"hpa_warning,omitempty"`
}

type Task struct {
	clientset kubernetes.Interface
}

func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

func (t *Task) Name() string {
	return TaskName
}

func (t *Task) Execute(ctx context.Context, payload json.RawMessage) (*task.Result, error) {
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		return task.NewErrorResult(fmt.Sprintf("failed to unmarshal payload: %v", err)), nil
	}

	if err := t.validatePayload(&p); err != nil {
		return task.NewErrorResult(err.Error()), nil
	}

	// Check namespace annotation
	ns, err := t.clientset.CoreV1().Namespaces().Get(ctx, p.Namespace, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("namespace not found: %s", p.Namespace)), nil
		}
		return nil, fmt.Errorf("failed to get namespace: %w", err)
	}

	if ns.Annotations[NoScaleAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("namespace %s has %s annotation set to true", p.Namespace, NoScaleAnnotation)), nil
	}

	switch p.Kind {
	case "deployment", "Deployment":
		return t.scaleDeployment(ctx, &p)
	case "statefulset", "StatefulSet":
		return t.scaleStatefulSet(ctx, &p)
	default:
		return task.NewErrorResult(fmt.Sprintf("unsupported kind: %s (only deployment and statefulset are supported)", p.Kind)), nil
	}
}

func (t *Task) validatePayload(p *Payload) error {
	if p.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Kind == "" {
		return fmt.Errorf("kind is required")
	}

	// Normalize kind
	switch p.Kind {
	case "deployment", "Deployment":
		// Valid
	case "statefulset", "StatefulSet":
		// Valid
	case "daemonset", "DaemonSet":
		return fmt.Errorf("daemonsets cannot be scaled")
	default:
		return fmt.Errorf("kind must be deployment or statefulset")
	}

	if p.Replicas < 0 {
		return fmt.Errorf("replicas must be >= 0")
	}

	if p.Replicas == 0 && !p.AllowScaleToZero {
		return fmt.Errorf("scaling to zero replicas requires allow_scale_to_zero to be true")
	}

	return nil
}

func (t *Task) scaleDeployment(ctx context.Context, p *Payload) (*task.Result, error) {
	// Get deployment
	deployment, err := t.clientset.AppsV1().Deployments(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("deployment not found: %s/%s", p.Namespace, p.Name)), nil
		}
		return nil, fmt.Errorf("failed to get deployment: %w", err)
	}

	// Check workload annotation
	if deployment.Annotations[NoScaleAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("deployment %s/%s has %s annotation set to true", p.Namespace, p.Name, NoScaleAnnotation)), nil
	}

	currentReplicas := int32(0)
	if deployment.Spec.Replicas != nil {
		currentReplicas = *deployment.Spec.Replicas
	}

	// Check 3x scale limit
	if currentReplicas > 0 && p.Replicas > currentReplicas*3 {
		return task.NewErrorResult(fmt.Sprintf("cannot scale more than 3x current replicas (current: %d, requested: %d, max allowed: %d)", currentReplicas, p.Replicas, currentReplicas*3)), nil
	}

	// Check for HPA
	hpaWarning, err := t.checkHPA(ctx, p.Namespace, p.Name, "Deployment")
	if err != nil {
		return nil, fmt.Errorf("failed to check for HPA: %w", err)
	}

	details := &ScaleDetails{
		DryRun:           p.DryRun,
		PreviousReplicas: currentReplicas,
		NewReplicas:      p.Replicas,
		HPAWarning:       hpaWarning,
	}

	// Handle dry-run
	if p.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would scale deployment %s/%s from %d to %d replicas", p.Namespace, p.Name, currentReplicas, p.Replicas),
			details,
		), nil
	}

	// Use UpdateScale API
	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.Name,
			Namespace: p.Namespace,
		},
		Spec: autoscalingv1.ScaleSpec{
			Replicas: p.Replicas,
		},
	}

	_, err = t.clientset.AppsV1().Deployments(p.Namespace).UpdateScale(ctx, p.Name, scale, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to scale deployment: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("Deployment %s/%s scaled from %d to %d replicas", p.Namespace, p.Name, currentReplicas, p.Replicas),
		details,
	), nil
}

func (t *Task) scaleStatefulSet(ctx context.Context, p *Payload) (*task.Result, error) {
	// Get statefulset
	statefulSet, err := t.clientset.AppsV1().StatefulSets(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewErrorResult(fmt.Sprintf("statefulset not found: %s/%s", p.Namespace, p.Name)), nil
		}
		return nil, fmt.Errorf("failed to get statefulset: %w", err)
	}

	// Check workload annotation
	if statefulSet.Annotations[NoScaleAnnotation] == "true" {
		return task.NewErrorResult(fmt.Sprintf("statefulset %s/%s has %s annotation set to true", p.Namespace, p.Name, NoScaleAnnotation)), nil
	}

	currentReplicas := int32(0)
	if statefulSet.Spec.Replicas != nil {
		currentReplicas = *statefulSet.Spec.Replicas
	}

	// Check 3x scale limit
	if currentReplicas > 0 && p.Replicas > currentReplicas*3 {
		return task.NewErrorResult(fmt.Sprintf("cannot scale more than 3x current replicas (current: %d, requested: %d, max allowed: %d)", currentReplicas, p.Replicas, currentReplicas*3)), nil
	}

	// Check for HPA
	hpaWarning, err := t.checkHPA(ctx, p.Namespace, p.Name, "StatefulSet")
	if err != nil {
		return nil, fmt.Errorf("failed to check for HPA: %w", err)
	}

	details := &ScaleDetails{
		DryRun:           p.DryRun,
		PreviousReplicas: currentReplicas,
		NewReplicas:      p.Replicas,
		HPAWarning:       hpaWarning,
	}

	// Handle dry-run
	if p.DryRun {
		return task.NewSuccessResultWithDetails(
			fmt.Sprintf("[DRY-RUN] Would scale statefulset %s/%s from %d to %d replicas", p.Namespace, p.Name, currentReplicas, p.Replicas),
			details,
		), nil
	}

	// Use UpdateScale API
	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.Name,
			Namespace: p.Namespace,
		},
		Spec: autoscalingv1.ScaleSpec{
			Replicas: p.Replicas,
		},
	}

	_, err = t.clientset.AppsV1().StatefulSets(p.Namespace).UpdateScale(ctx, p.Name, scale, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to scale statefulset: %w", err)
	}

	return task.NewSuccessResultWithDetails(
		fmt.Sprintf("StatefulSet %s/%s scaled from %d to %d replicas", p.Namespace, p.Name, currentReplicas, p.Replicas),
		details,
	), nil
}

func (t *Task) checkHPA(ctx context.Context, namespace, name, kind string) (string, error) {
	hpaList, err := t.clientset.AutoscalingV1().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, hpa := range hpaList.Items {
		if hpa.Spec.ScaleTargetRef.Kind == kind && hpa.Spec.ScaleTargetRef.Name == name {
			return fmt.Sprintf("Warning: %s %s/%s is managed by HPA %s. Manual scaling may be overridden.", kind, namespace, name, hpa.Name), nil
		}
	}

	return "", nil
}
