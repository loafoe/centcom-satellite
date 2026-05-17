package list_argocd_applications

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/pico-agent/internal/task"
)

const TaskName = "list_argocd_applications"

var applicationGVR = schema.GroupVersionResource{
	Group:    "argoproj.io",
	Version:  "v1alpha1",
	Resource: "applications",
}

type Payload struct {
	Namespace string `json:"namespace,omitempty"`
	Project   string `json:"project,omitempty"`
}

type ApplicationList struct {
	Total           int               `json:"total"`
	ArgocdInstalled bool              `json:"argocd_installed"`
	Applications    []ApplicationInfo `json:"applications"`
}

type ApplicationInfo struct {
	Name           string          `json:"name"`
	Namespace      string          `json:"namespace"`
	Project        string          `json:"project"`
	Health         HealthStatus    `json:"health"`
	Sync           SyncStatus      `json:"sync"`
	Source         SourceInfo      `json:"source"`
	Destination    DestinationInfo `json:"destination"`
	OperationState string          `json:"operation_state,omitempty"`
	LastSyncedAt   string          `json:"last_synced_at,omitempty"`
	Age            string          `json:"age"`
}

type HealthStatus struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type SyncStatus struct {
	Status   string `json:"status"`
	Revision string `json:"revision,omitempty"`
}

type SourceInfo struct {
	RepoURL        string `json:"repoURL,omitempty"`
	Path           string `json:"path,omitempty"`
	TargetRevision string `json:"targetRevision,omitempty"`
	Chart          string `json:"chart,omitempty"`
}

type DestinationInfo struct {
	Server    string `json:"server,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type Task struct {
	dynamicClient dynamic.Interface
}

func New(dynamicClient dynamic.Interface) *Task {
	return &Task{dynamicClient: dynamicClient}
}

func (t *Task) Name() string {
	return TaskName
}

func (t *Task) Execute(ctx context.Context, rawPayload json.RawMessage) (*task.Result, error) {
	var payload Payload
	if len(rawPayload) > 0 && string(rawPayload) != "{}" {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return task.NewErrorResult(fmt.Sprintf("invalid payload: %v", err)), nil
		}
	}

	var apps *unstructured.UnstructuredList
	var err error

	if payload.Namespace != "" {
		apps, err = t.dynamicClient.Resource(applicationGVR).Namespace(payload.Namespace).List(ctx, metav1.ListOptions{})
	} else {
		apps, err = t.dynamicClient.Resource(applicationGVR).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		if isCRDNotInstalled(err) {
			return task.NewSuccessResultWithDetails(
				"Argo CD CRDs not installed in this cluster",
				&ApplicationList{Total: 0, ArgocdInstalled: false, Applications: []ApplicationInfo{}},
			), nil
		}
		return nil, fmt.Errorf("failed to list argocd applications: %w", err)
	}

	result := &ApplicationList{
		ArgocdInstalled: true,
		Applications:    make([]ApplicationInfo, 0, len(apps.Items)),
	}

	for i := range apps.Items {
		app := &apps.Items[i]
		info := buildApplicationInfo(app)

		if payload.Project != "" && info.Project != payload.Project {
			continue
		}

		result.Applications = append(result.Applications, info)
	}

	result.Total = len(result.Applications)

	sort.Slice(result.Applications, func(i, j int) bool {
		return result.Applications[i].Name < result.Applications[j].Name
	})

	msg := fmt.Sprintf("Found %d Argo CD applications", result.Total)
	if payload.Project != "" {
		msg = fmt.Sprintf("Found %d Argo CD applications in project %s", result.Total, payload.Project)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func buildApplicationInfo(app *unstructured.Unstructured) ApplicationInfo {
	info := ApplicationInfo{
		Name:      app.GetName(),
		Namespace: app.GetNamespace(),
		Age:       formatAge(app.GetCreationTimestamp().Time),
	}

	// spec.project
	if project, found, err := unstructured.NestedString(app.Object, "spec", "project"); err == nil && found {
		info.Project = project
	}

	// spec.source
	if repoURL, found, err := unstructured.NestedString(app.Object, "spec", "source", "repoURL"); err == nil && found {
		info.Source.RepoURL = repoURL
	}
	if path, found, err := unstructured.NestedString(app.Object, "spec", "source", "path"); err == nil && found {
		info.Source.Path = path
	}
	if targetRevision, found, err := unstructured.NestedString(app.Object, "spec", "source", "targetRevision"); err == nil && found {
		info.Source.TargetRevision = targetRevision
	}
	if chart, found, err := unstructured.NestedString(app.Object, "spec", "source", "chart"); err == nil && found {
		info.Source.Chart = chart
	}

	// spec.destination
	if server, found, err := unstructured.NestedString(app.Object, "spec", "destination", "server"); err == nil && found {
		info.Destination.Server = server
	}
	if ns, found, err := unstructured.NestedString(app.Object, "spec", "destination", "namespace"); err == nil && found {
		info.Destination.Namespace = ns
	}

	// status.health
	if healthStatus, found, err := unstructured.NestedString(app.Object, "status", "health", "status"); err == nil && found {
		info.Health.Status = healthStatus
	}
	if healthMsg, found, err := unstructured.NestedString(app.Object, "status", "health", "message"); err == nil && found {
		info.Health.Message = healthMsg
	}

	// status.sync
	if syncStatus, found, err := unstructured.NestedString(app.Object, "status", "sync", "status"); err == nil && found {
		info.Sync.Status = syncStatus
	}
	if revision, found, err := unstructured.NestedString(app.Object, "status", "sync", "revision"); err == nil && found {
		info.Sync.Revision = revision
	}

	// status.operationState
	if phase, found, err := unstructured.NestedString(app.Object, "status", "operationState", "phase"); err == nil && found {
		info.OperationState = phase
	}
	if finishedAt, found, err := unstructured.NestedString(app.Object, "status", "operationState", "finishedAt"); err == nil && found {
		info.LastSyncedAt = finishedAt
	} else if reconciledAt, found, err := unstructured.NestedString(app.Object, "status", "reconciledAt"); err == nil && found {
		info.LastSyncedAt = reconciledAt
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

func isCRDNotInstalled(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "the server could not find the requested resource") ||
		strings.Contains(errStr, "no matches for kind")
}
