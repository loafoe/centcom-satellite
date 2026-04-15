// Package storage_status provides PVC/PV health check functionality.
package storage_status

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "storage_status"

// Payload for storage_status task.
type Payload struct {
	// Namespace filters to a specific namespace (default: all namespaces)
	Namespace string `json:"namespace,omitempty"`
}

// StorageReport contains the storage health summary.
type StorageReport struct {
	Healthy          bool              `json:"healthy"`
	Summary          string            `json:"summary"`
	PVCSummary       PVCSummary        `json:"pvc_summary"`
	PVSummary        PVSummary         `json:"pv_summary"`
	ProblematicPVCs  []ProblematicPVC  `json:"problematic_pvcs,omitempty"`
	ProblematicPVs   []ProblematicPV   `json:"problematic_pvs,omitempty"`
	StorageClasses   []StorageClassInfo `json:"storage_classes"`
}

// PVCSummary contains PVC statistics.
type PVCSummary struct {
	Total    int `json:"total"`
	Bound    int `json:"bound"`
	Pending  int `json:"pending"`
	Lost     int `json:"lost"`
}

// PVSummary contains PV statistics.
type PVSummary struct {
	Total     int `json:"total"`
	Available int `json:"available"`
	Bound     int `json:"bound"`
	Released  int `json:"released"`
	Failed    int `json:"failed"`
}

// ProblematicPVC represents a PVC with issues.
type ProblematicPVC struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Phase            string `json:"phase"`
	StorageClass     string `json:"storage_class,omitempty"`
	RequestedSize    string `json:"requested_size"`
	Reason           string `json:"reason,omitempty"`
	Message          string `json:"message,omitempty"`
}

// ProblematicPV represents a PV with issues.
type ProblematicPV struct {
	Name          string `json:"name"`
	Phase         string `json:"phase"`
	ReclaimPolicy string `json:"reclaim_policy"`
	StorageClass  string `json:"storage_class,omitempty"`
	Capacity      string `json:"capacity"`
	Reason        string `json:"reason,omitempty"`
	Message       string `json:"message,omitempty"`
}

// StorageClassInfo contains storage class details.
type StorageClassInfo struct {
	Name             string `json:"name"`
	Provisioner      string `json:"provisioner"`
	AllowExpansion   bool   `json:"allow_expansion"`
	ReclaimPolicy    string `json:"reclaim_policy"`
	VolumeBinding    string `json:"volume_binding"`
	IsDefault        bool   `json:"is_default"`
}

// Task handles storage status checks.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new storage status task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute performs the storage status check.
func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	report := &StorageReport{
		Healthy: true,
	}

	namespace := payload.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	// Check PVCs
	pvcs, err := t.clientset.CoreV1().PersistentVolumeClaims(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list PVCs: %w", err)
	}

	report.PVCSummary = t.summarizePVCs(pvcs, report)

	// Check PVs (cluster-wide resource)
	pvs, err := t.clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list PVs: %w", err)
	}

	report.PVSummary = t.summarizePVs(pvs, report)

	// Get storage classes
	scs, err := t.clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list storage classes: %w", err)
	}

	for _, sc := range scs.Items {
		reclaimPolicy := "Delete"
		if sc.ReclaimPolicy != nil {
			reclaimPolicy = string(*sc.ReclaimPolicy)
		}
		volumeBinding := "Immediate"
		if sc.VolumeBindingMode != nil {
			volumeBinding = string(*sc.VolumeBindingMode)
		}
		allowExpansion := false
		if sc.AllowVolumeExpansion != nil {
			allowExpansion = *sc.AllowVolumeExpansion
		}

		isDefault := false
		if v, ok := sc.Annotations["storageclass.kubernetes.io/is-default-class"]; ok && v == "true" {
			isDefault = true
		}

		report.StorageClasses = append(report.StorageClasses, StorageClassInfo{
			Name:           sc.Name,
			Provisioner:    sc.Provisioner,
			AllowExpansion: allowExpansion,
			ReclaimPolicy:  reclaimPolicy,
			VolumeBinding:  volumeBinding,
			IsDefault:      isDefault,
		})
	}

	// Determine health
	if report.PVCSummary.Pending > 0 || report.PVCSummary.Lost > 0 ||
		report.PVSummary.Failed > 0 || report.PVSummary.Released > 0 {
		report.Healthy = false
	}

	// Build summary
	report.Summary = t.buildSummary(report)

	return task.NewSuccessResultWithDetails(report.Summary, report), nil
}

func (t *Task) summarizePVCs(pvcs *corev1.PersistentVolumeClaimList, report *StorageReport) PVCSummary {
	summary := PVCSummary{Total: len(pvcs.Items)}

	for _, pvc := range pvcs.Items {
		switch pvc.Status.Phase {
		case corev1.ClaimBound:
			summary.Bound++
		case corev1.ClaimPending:
			summary.Pending++
			report.ProblematicPVCs = append(report.ProblematicPVCs, t.pvcToProblematic(&pvc))
		case corev1.ClaimLost:
			summary.Lost++
			report.ProblematicPVCs = append(report.ProblematicPVCs, t.pvcToProblematic(&pvc))
		}
	}

	return summary
}

func (t *Task) pvcToProblematic(pvc *corev1.PersistentVolumeClaim) ProblematicPVC {
	p := ProblematicPVC{
		Namespace:     pvc.Namespace,
		Name:          pvc.Name,
		Phase:         string(pvc.Status.Phase),
		RequestedSize: pvc.Spec.Resources.Requests.Storage().String(),
	}
	if pvc.Spec.StorageClassName != nil {
		p.StorageClass = *pvc.Spec.StorageClassName
	}

	// Try to get reason from conditions
	for _, cond := range pvc.Status.Conditions {
		if cond.Status == corev1.ConditionTrue || cond.Status == corev1.ConditionFalse {
			if cond.Reason != "" {
				p.Reason = cond.Reason
			}
			if cond.Message != "" {
				p.Message = cond.Message
			}
		}
	}

	return p
}

func (t *Task) summarizePVs(pvs *corev1.PersistentVolumeList, report *StorageReport) PVSummary {
	summary := PVSummary{Total: len(pvs.Items)}

	for _, pv := range pvs.Items {
		switch pv.Status.Phase {
		case corev1.VolumeAvailable:
			summary.Available++
		case corev1.VolumeBound:
			summary.Bound++
		case corev1.VolumeReleased:
			summary.Released++
			report.ProblematicPVs = append(report.ProblematicPVs, t.pvToProblematic(&pv))
		case corev1.VolumeFailed:
			summary.Failed++
			report.ProblematicPVs = append(report.ProblematicPVs, t.pvToProblematic(&pv))
		}
	}

	return summary
}

func (t *Task) pvToProblematic(pv *corev1.PersistentVolume) ProblematicPV {
	p := ProblematicPV{
		Name:          pv.Name,
		Phase:         string(pv.Status.Phase),
		ReclaimPolicy: string(pv.Spec.PersistentVolumeReclaimPolicy),
		Capacity:      pv.Spec.Capacity.Storage().String(),
	}
	if pv.Spec.StorageClassName != "" {
		p.StorageClass = pv.Spec.StorageClassName
	}
	if pv.Status.Reason != "" {
		p.Reason = pv.Status.Reason
	}
	if pv.Status.Message != "" {
		p.Message = pv.Status.Message
	}

	return p
}

func (t *Task) buildSummary(report *StorageReport) string {
	if report.Healthy {
		return fmt.Sprintf("Storage healthy: %d PVCs bound, %d PVs available",
			report.PVCSummary.Bound, report.PVSummary.Available+report.PVSummary.Bound)
	}

	var issues []string
	if report.PVCSummary.Pending > 0 {
		issues = append(issues, fmt.Sprintf("%d pending PVCs", report.PVCSummary.Pending))
	}
	if report.PVCSummary.Lost > 0 {
		issues = append(issues, fmt.Sprintf("%d lost PVCs", report.PVCSummary.Lost))
	}
	if report.PVSummary.Released > 0 {
		issues = append(issues, fmt.Sprintf("%d released PVs", report.PVSummary.Released))
	}
	if report.PVSummary.Failed > 0 {
		issues = append(issues, fmt.Sprintf("%d failed PVs", report.PVSummary.Failed))
	}

	return fmt.Sprintf("Storage issues: %v", issues)
}
