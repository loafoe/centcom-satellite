// Package list_endpoints provides EndpointSlice listing functionality.
package list_endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const TaskName = "list_endpoints"

// Payload for list_endpoints task.
type Payload struct {
	Namespace     string `json:"namespace,omitempty"`
	ServiceName   string `json:"service_name,omitempty"`
	LabelSelector string `json:"label_selector,omitempty"`
}

// EndpointSliceList contains the endpoint slice listing.
type EndpointSliceList struct {
	Total  int                 `json:"total"`
	Slices []EndpointSliceInfo `json:"slices"`
}

// EndpointSliceInfo contains endpoint slice details.
type EndpointSliceInfo struct {
	Name        string         `json:"name"`
	Namespace   string         `json:"namespace"`
	ServiceName string         `json:"service_name"`
	AddressType string         `json:"address_type"`
	Endpoints   []EndpointInfo `json:"endpoints"`
	Ports       []PortInfo     `json:"ports"`
	Age         string         `json:"age"`
}

// EndpointInfo contains endpoint details.
type EndpointInfo struct {
	Addresses  []string       `json:"addresses"`
	Conditions ConditionsInfo `json:"conditions"`
	NodeName   string         `json:"node_name,omitempty"`
	TargetRef  string         `json:"target_ref,omitempty"`
}

// ConditionsInfo contains endpoint conditions.
type ConditionsInfo struct {
	Ready       *bool `json:"ready,omitempty"`
	Serving     *bool `json:"serving,omitempty"`
	Terminating *bool `json:"terminating,omitempty"`
}

// PortInfo contains port details.
type PortInfo struct {
	Name     string `json:"name,omitempty"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

// Task handles endpoint slice listing.
type Task struct {
	clientset kubernetes.Interface
}

// New creates a new list endpoints task.
func New(clientset kubernetes.Interface) *Task {
	return &Task{clientset: clientset}
}

// Name returns the task type identifier.
func (t *Task) Name() string {
	return TaskName
}

// Execute lists endpoint slices.
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

	listOpts := metav1.ListOptions{}
	if payload.ServiceName != "" {
		listOpts.LabelSelector = fmt.Sprintf("kubernetes.io/service-name=%s", payload.ServiceName)
	} else if payload.LabelSelector != "" {
		listOpts.LabelSelector = payload.LabelSelector
	}

	slices, err := t.clientset.DiscoveryV1().EndpointSlices(namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list endpoint slices: %w", err)
	}

	result := &EndpointSliceList{
		Total:  len(slices.Items),
		Slices: make([]EndpointSliceInfo, 0, len(slices.Items)),
	}

	for i := range slices.Items {
		slice := &slices.Items[i]
		sliceInfo := t.buildSliceInfo(slice)
		result.Slices = append(result.Slices, sliceInfo)
	}

	sort.Slice(result.Slices, func(i, j int) bool {
		if result.Slices[i].Namespace != result.Slices[j].Namespace {
			return result.Slices[i].Namespace < result.Slices[j].Namespace
		}
		if result.Slices[i].ServiceName != result.Slices[j].ServiceName {
			return result.Slices[i].ServiceName < result.Slices[j].ServiceName
		}
		return result.Slices[i].Name < result.Slices[j].Name
	})

	msg := fmt.Sprintf("Found %d endpoint slices", result.Total)
	if namespace != metav1.NamespaceAll {
		msg = fmt.Sprintf("Found %d endpoint slices in namespace %s", result.Total, namespace)
	}
	return task.NewSuccessResultWithDetails(msg, result), nil
}

func (t *Task) buildSliceInfo(slice *discoveryv1.EndpointSlice) EndpointSliceInfo {
	info := EndpointSliceInfo{
		Name:        slice.Name,
		Namespace:   slice.Namespace,
		ServiceName: slice.Labels["kubernetes.io/service-name"],
		AddressType: string(slice.AddressType),
		Age:         formatAge(slice.CreationTimestamp.Time),
		Endpoints:   make([]EndpointInfo, 0, len(slice.Endpoints)),
		Ports:       make([]PortInfo, 0, len(slice.Ports)),
	}

	for _, ep := range slice.Endpoints {
		epInfo := EndpointInfo{
			Addresses: ep.Addresses,
			Conditions: ConditionsInfo{
				Ready:       ep.Conditions.Ready,
				Serving:     ep.Conditions.Serving,
				Terminating: ep.Conditions.Terminating,
			},
		}
		if ep.NodeName != nil {
			epInfo.NodeName = *ep.NodeName
		}
		if ep.TargetRef != nil {
			epInfo.TargetRef = fmt.Sprintf("%s/%s", ep.TargetRef.Kind, ep.TargetRef.Name)
		}
		info.Endpoints = append(info.Endpoints, epInfo)
	}

	for _, port := range slice.Ports {
		portInfo := PortInfo{
			Protocol: string(*port.Protocol),
		}
		if port.Name != nil {
			portInfo.Name = *port.Name
		}
		if port.Port != nil {
			portInfo.Port = *port.Port
		}
		info.Ports = append(info.Ports, portInfo)
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
