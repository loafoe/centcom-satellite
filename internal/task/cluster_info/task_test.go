package cluster_info

import (
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
