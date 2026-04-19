// Package k8s provides Kubernetes client initialization.
package k8s

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the Kubernetes clientset.
type Client struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
	RESTMapper    meta.RESTMapper
}

// NewClient creates a new Kubernetes client.
// It first attempts to use in-cluster config, then falls back to kubeconfig.
func NewClient() (*Client, error) {
	config, err := getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}

	groupResources, err := restmapper.GetAPIGroupResources(discoveryClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get API group resources: %w", err)
	}

	restMapper := restmapper.NewDiscoveryRESTMapper(groupResources)

	return &Client{
		Clientset:     clientset,
		DynamicClient: dynamicClient,
		RESTMapper:    restMapper,
	}, nil
}

// NewClientWithInterface creates a client with a provided interface (for testing).
func NewClientWithInterface(clientset kubernetes.Interface) *Client {
	return &Client{Clientset: clientset}
}

func getConfig() (*rest.Config, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err == nil {
		slog.Info("using in-cluster kubernetes config")
		return config, nil
	}

	slog.Debug("in-cluster config not available, trying kubeconfig", "error", err)

	// Fall back to kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
	}

	slog.Info("using kubeconfig", "path", kubeconfig)
	return config, nil
}
