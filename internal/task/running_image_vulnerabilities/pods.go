package running_image_vulnerabilities

import (
	"context"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ecrHost matches a private ECR registry host: <account>.dkr.ecr.<region>.amazonaws.com[.cn].
var ecrHost = regexp.MustCompile(`^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

// runningImage is one distinct image digest running in the cluster.
type runningImage struct {
	registry string // account ID ("" for non-ECR)
	repo     string
	digest   string
	display  string // the pod spec's image reference, e.g. repo:tag
	// platforms are the per-platform manifest digests Inspector scans.
	platforms []string
	workloads map[string]bool
	assessed  bool
	matched   bool
}

// parseImageID splits a containerStatus imageID
// ("[docker-pullable://]host/repo@sha256:...") into host, repo and digest.
func parseImageID(imageID string) (host, repo, digest string, ok bool) {
	ref := imageID
	if i := strings.Index(ref, "://"); i >= 0 {
		ref = ref[i+3:]
	}
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return "", "", "", false
	}
	name, digest := ref[:at], ref[at+1:]
	if !strings.HasPrefix(digest, "sha256:") {
		return "", "", "", false
	}
	slash := strings.Index(name, "/")
	if slash < 0 {
		return "docker.io", name, digest, true
	}
	return name[:slash], name[slash+1:], digest, true
}

// workloadOf names the workload owning pod as namespace/Kind/name,
// collapsing a Deployment's ReplicaSet to the Deployment.
func workloadOf(pod *corev1.Pod) string {
	for _, o := range pod.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		kind, name := o.Kind, o.Name
		if kind == "ReplicaSet" {
			if h := pod.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(name, "-"+h) {
				kind, name = "Deployment", strings.TrimSuffix(name, "-"+h)
			}
		}
		return pod.Namespace + "/" + kind + "/" + name
	}
	return pod.Namespace + "/Pod/" + pod.Name
}

// collectPods records every image digest used by a live pod's containers
// (init containers included: they ran this image too).
func (s *scan) collectPods(ctx context.Context, cs kubernetes.Interface) error {
	s.images = map[string]*runningImage{}
	other := map[string]bool{}
	namespaces := s.payload.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{metav1.NamespaceAll}
	}
	for _, ns := range namespaces {
		cont := ""
		for {
			list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: 500, Continue: cont})
			if err != nil {
				return err
			}
			for i := range list.Items {
				pod := &list.Items[i]
				if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
					continue
				}
				s.report.Coverage.RunningContainers += len(pod.Status.ContainerStatuses)
				wl := workloadOf(pod)
				statuses := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
				for _, cst := range statuses {
					s.addImage(cst, wl, other)
				}
			}
			cont = list.Continue
			if cont == "" {
				break
			}
		}
	}
	s.report.Coverage.RunningImages = len(s.images)
	for _, img := range s.images {
		if img.registry != "" {
			s.report.Coverage.ECRImages++
		} else {
			s.report.Coverage.OtherRegistryImages++
		}
	}
	for host := range other {
		if len(s.report.Coverage.OtherRegistries) < maxListed {
			s.report.Coverage.OtherRegistries = append(s.report.Coverage.OtherRegistries, host)
		}
	}
	sortStrings(s.report.Coverage.OtherRegistries)
	return nil
}

func (s *scan) addImage(cst corev1.ContainerStatus, workload string, other map[string]bool) {
	host, repo, digest, ok := parseImageID(cst.ImageID)
	if !ok {
		return
	}
	key := host + "/" + repo + "@" + digest
	img := s.images[key]
	if img == nil {
		img = &runningImage{repo: repo, digest: digest, display: cst.Image, workloads: map[string]bool{}}
		if m := ecrHost.FindStringSubmatch(host); m != nil && m[1] == s.account && m[2] == s.region {
			img.registry = m[1]
		} else {
			other[host] = true
		}
		s.images[key] = img
	}
	img.workloads[workload] = true
}
