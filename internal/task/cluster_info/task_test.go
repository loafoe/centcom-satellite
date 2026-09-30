package cluster_info

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeResourceLister struct {
	resources map[string]*metav1.APIResourceList
}

func (f *fakeResourceLister) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if list, ok := f.resources[groupVersion]; ok {
		return list, nil
	}
	return nil, errors.New("not found")
}

func TestDiscoverHelmApplicationVersion_PrefersV1(t *testing.T) {
	fake := &fakeResourceLister{resources: map[string]*metav1.APIResourceList{
		"dip.io/v1":       {APIResources: []metav1.APIResource{{Kind: "HelmApplication"}}},
		"dip.io/v1alpha1": {APIResources: []metav1.APIResource{{Kind: "HelmApplication"}}},
	}}
	supported, version := discoverHelmApplicationVersion(fake, true)
	if !supported || version != "v1" {
		t.Fatalf("got supported=%v version=%q, want true/v1", supported, version)
	}
}

func TestDiscoverHelmApplicationVersion_FallsBackToV1Alpha1(t *testing.T) {
	fake := &fakeResourceLister{resources: map[string]*metav1.APIResourceList{
		"dip.io/v1alpha1": {APIResources: []metav1.APIResource{{Kind: "HelmApplication"}}},
	}}
	supported, version := discoverHelmApplicationVersion(fake, true)
	if !supported || version != "v1alpha1" {
		t.Fatalf("got supported=%v version=%q, want true/v1alpha1", supported, version)
	}
}

func TestDiscoverHelmApplicationVersion_AbsentCRD(t *testing.T) {
	fake := &fakeResourceLister{resources: map[string]*metav1.APIResourceList{}}
	supported, version := discoverHelmApplicationVersion(fake, true)
	if supported || version != "" {
		t.Fatalf("got supported=%v version=%q, want false/\"\" when the CRD isn't served anywhere", supported, version)
	}
}

func TestDiscoverHelmApplicationVersion_FalseWhenGetResourceDisabled(t *testing.T) {
	// Even if the CRD is genuinely served, capability discovery must report
	// unsupported if get_resource/list_resources aren't registered on this
	// satellite, since Applications reads depend on those tasks.
	fake := &fakeResourceLister{resources: map[string]*metav1.APIResourceList{
		"dip.io/v1": {APIResources: []metav1.APIResource{{Kind: "HelmApplication"}}},
	}}
	supported, version := discoverHelmApplicationVersion(fake, false)
	if supported || version != "" {
		t.Fatalf("got supported=%v version=%q, want false/\"\" when get_resource is disabled", supported, version)
	}
}

// TestExecute_DiscoversHelmApplicationLivePerCall proves the discovery is
// genuinely live per Execute() call, not baked into the static
// WithCapabilities snapshot taken once at construction - if someone moved
// the call into New()/WithCapabilities, or swapped in a cached discovery
// client, this test (unlike the pure discoverHelmApplicationVersion unit
// tests above) would catch it: the fake clientset's discovery resources are
// mutated *between* two Execute() calls on the same *Task.
func TestExecute_DiscoversHelmApplicationLivePerCall(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	fakeDiscovery, ok := clientset.Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatal("expected clientset.Discovery() to be *discoveryfake.FakeDiscovery")
	}

	task := New(clientset).WithCapabilities(Capabilities{GetResource: true})

	// First call: CRD not yet installed.
	fakeDiscovery.Resources = []*metav1.APIResourceList{}
	result1, err := task.Execute(context.Background(), json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("Execute (before CRD installed): %v", err)
	}
	ci1, ok := result1.Details.(*ClusterInfo)
	if !ok {
		t.Fatalf("expected result1.Details to be *ClusterInfo, got %T", result1.Details)
	}
	if ci1.Capabilities.HelmApplication {
		t.Fatal("expected HelmApplication=false before the CRD is installed")
	}

	// Simulate the CRD being installed on the live cluster after this
	// process started, with no restart - the exact scenario a
	// startup-time-only snapshot would get wrong forever.
	fakeDiscovery.Resources = []*metav1.APIResourceList{
		{GroupVersion: "dip.io/v1alpha1", APIResources: []metav1.APIResource{{Kind: "HelmApplication"}}},
	}
	result2, err := task.Execute(context.Background(), json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("Execute (after CRD installed): %v", err)
	}
	ci2, ok := result2.Details.(*ClusterInfo)
	if !ok {
		t.Fatalf("expected result2.Details to be *ClusterInfo, got %T", result2.Details)
	}
	if !ci2.Capabilities.HelmApplication {
		t.Fatal("expected HelmApplication=true immediately after the CRD is installed, with no restart - discovery must be live per call")
	}
	if ci2.Capabilities.HelmApplicationVersion != "v1alpha1" {
		t.Fatalf("expected version v1alpha1, got %q", ci2.Capabilities.HelmApplicationVersion)
	}
}

// TestExecute_ReportsHelmApplicationWriteCapability guards centcom's
// ability to show/hide write-action buttons (Deploy/Sync/Delete) per
// satellite: unlike HelmApplication/HelmApplicationVersion (live-discovered
// CRD state), HelmApplicationWrite is a static passthrough of this
// process's own config (HELM_APPLICATION_WRITE_ENABLED) - it must round-trip
// through WithCapabilities/Execute unchanged, the same as every other
// static capability flag (GetResource, Argocd, etc.).
func TestExecute_ReportsHelmApplicationWriteCapability(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset).WithCapabilities(Capabilities{HelmApplicationWrite: true})

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	ci, ok := result.Details.(*ClusterInfo)
	if !ok {
		t.Fatalf("expected result.Details to be *ClusterInfo, got %T", result.Details)
	}
	if !ci.Capabilities.HelmApplicationWrite {
		t.Fatal("expected HelmApplicationWrite=true to round-trip from WithCapabilities")
	}
}
