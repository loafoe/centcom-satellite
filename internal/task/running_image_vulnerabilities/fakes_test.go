package running_image_vulnerabilities

import (
	"context"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testAccount = "111111111111"
	testRegion  = "us-east-1"
	testHost    = testAccount + ".dkr.ecr." + testRegion + ".amazonaws.com"
)

// fakeECR serves manifests by digest.
type fakeECR struct {
	manifests map[string]string // digest -> manifest JSON ("" = single-platform)
	mu        sync.Mutex
	calls     int
}

func (f *fakeECR) BatchGetImage(_ context.Context, in *ecr.BatchGetImageInput, _ ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	out := &ecr.BatchGetImageOutput{}
	for _, id := range in.ImageIds {
		d := aws.ToString(id.ImageDigest)
		m, ok := f.manifests[d]
		if !ok {
			out.Failures = append(out.Failures, ecrtypes.ImageFailure{ImageId: &id})
			continue
		}
		if m == "" {
			m = `{"schemaVersion":2,"layers":[]}`
		}
		out.Images = append(out.Images, ecrtypes.Image{ImageId: &ecrtypes.ImageIdentifier{ImageDigest: aws.String(d)}, ImageManifest: aws.String(m)})
	}
	return out, nil
}

// fakeInspector serves coverage by resource ARN suffix (digest) and
// findings by image hash, recording every ListFindings filter.
type fakeInspector struct {
	coverage map[string]itypes.ScanStatus // digest -> status
	findings map[string][]itypes.Finding  // digest -> findings
	mu       sync.Mutex
	filters  []*itypes.FilterCriteria
}

func (f *fakeInspector) ListCoverage(_ context.Context, in *inspector2.ListCoverageInput, _ ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error) {
	out := &inspector2.ListCoverageOutput{}
	for _, rf := range in.FilterCriteria.ResourceId {
		arn := aws.ToString(rf.Value)
		d := arn[strings.LastIndex(arn, "/")+1:]
		if st, ok := f.coverage[d]; ok {
			st := st
			out.CoveredResources = append(out.CoveredResources, itypes.CoveredResource{ResourceId: aws.String(arn), ScanStatus: &st})
		}
	}
	return out, nil
}

func (f *fakeInspector) ListFindings(_ context.Context, in *inspector2.ListFindingsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	f.mu.Lock()
	f.filters = append(f.filters, in.FilterCriteria)
	f.mu.Unlock()
	sevs := map[string]bool{}
	for _, s := range in.FilterCriteria.Severity {
		sevs[aws.ToString(s.Value)] = true
	}
	out := &inspector2.ListFindingsOutput{}
	for _, h := range in.FilterCriteria.EcrImageHash {
		for _, fd := range f.findings[aws.ToString(h.Value)] {
			if sevs[string(fd.Severity)] {
				out.Findings = append(out.Findings, fd)
			}
		}
	}
	return out, nil
}

func finding(repo, digest, cve, sev, pkg, ver, fixed string) itypes.Finding {
	return itypes.Finding{
		Title: aws.String(cve + " - " + pkg), Severity: itypes.Severity(sev),
		FixAvailable: itypes.FixAvailableYes, ExploitAvailable: itypes.ExploitAvailableYes,
		PackageVulnerabilityDetails: &itypes.PackageVulnerabilityDetails{
			VulnerabilityId:    aws.String(cve),
			VulnerablePackages: []itypes.VulnerablePackage{{Name: aws.String(pkg), Version: aws.String(ver), FixedInVersion: aws.String(fixed)}},
		},
		Resources: []itypes.Resource{{Details: &itypes.ResourceDetails{AwsEcrContainerImage: &itypes.AwsEcrContainerImageDetails{
			Registry: aws.String(testAccount), RepositoryName: aws.String(repo), ImageHash: aws.String(digest),
		}}}},
	}
}

// pod builds a running pod owned by Deployment deploy (via a ReplicaSet)
// whose single container runs imageID.
func pod(ns, name, deploy, image, imageID string) *corev1.Pod {
	ctrl := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: map[string]string{"pod-template-hash": "abc12"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: deploy + "-abc12", Controller: &ctrl}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Image: image, ImageID: imageID}}},
	}
}

func newTestTask(e *fakeECR, i *fakeInspector, pods ...*corev1.Pod) *Task {
	objs := make([]runtime.Object, 0, len(pods))
	for _, p := range pods {
		objs = append(objs, p)
	}
	t := New(fake.NewSimpleClientset(objs...))
	t.clients = func(context.Context, string) (ecrAPI, inspectorAPI, string, string, error) {
		return e, i, testRegion, testAccount, nil
	}
	return t
}
