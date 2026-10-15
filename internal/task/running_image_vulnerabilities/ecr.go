package running_image_vulnerabilities

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ecrBatch is BatchGetImage's max image IDs per call.
const ecrBatch = 100

var manifestMediaTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// Platform image scan statuses come from Inspector ListCoverage as
// "<statusCode>" or "<statusCode>/<reason>", e.g. "ACTIVE",
// "INACTIVE/SCAN_FREQUENCY_SCAN_ON_PUSH" (scanned on push: findings valid),
// "INACTIVE/SCAN_ELIGIBILITY_EXPIRED" (no longer scanned: no findings).
// statusNotCovered means Inspector has no coverage record for the image.
const statusNotCovered = "NOT_COVERED"

// gapReasons are INACTIVE reasons whose images have no current findings:
// a low count for them means unknown, not clean.
var gapReasons = map[string]bool{
	"SCAN_ELIGIBILITY_EXPIRED": true, "UNSUPPORTED_OS": true, "UNSUPPORTED_MEDIA_TYPE": true,
	"UNSUPPORTED_CONFIG_FILE": true, "IMAGE_SIZE_EXCEEDED": true, "STALE_INVENTORY": true,
	"DEEP_INSPECTION_NO_INVENTORY": true, "NO_INVENTORY": true, "INTERNAL_ERROR": true,
	"PENDING_INITIAL_SCAN": true, "ACCESS_DENIED": true, "RESOURCE_TERMINATED": true,
}

// isGap reports whether a platform image's status means its findings are
// missing or stale.
func isGap(status string) bool {
	if status == statusNotCovered {
		return true
	}
	if code, reason, ok := strings.Cut(status, "/"); ok && code == "INACTIVE" {
		return gapReasons[reason]
	}
	return false
}

type repoKey struct{ registry, repo string }

// resolveImages replaces each running ECR image's digest by its platform
// manifest digests and records their scan status, one repository per worker.
func (s *scan) resolveImages(ctx context.Context) error {
	byRepo := map[repoKey][]*runningImage{}
	for _, img := range s.images {
		if img.registry != "" {
			k := repoKey{img.registry, img.repo}
			byRepo[k] = append(byRepo[k], img)
		}
	}
	repos := make([]repoKey, 0, len(byRepo))
	for k := range byRepo {
		repos = append(repos, k)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].registry+"/"+repos[i].repo < repos[j].registry+"/"+repos[j].repo })
	s.platforms = map[platformKey][]*runningImage{}
	s.status = map[platformKey]string{}
	return forEach(len(repos), func(i int) error {
		return s.resolveRepo(ctx, repos[i], byRepo[repos[i]])
	})
}

type platformKey struct{ registry, repo, digest string }

// resolveRepo resolves one repository's running images into local state
// and merges it into the scan once the repository is done.
func (s *scan) resolveRepo(ctx context.Context, k repoKey, imgs []*runningImage) error {
	platforms := map[*runningImage][]string{}
	unresolved := 0
	for start := 0; start < len(imgs); start += ecrBatch {
		n, err := s.resolveBatch(ctx, k, imgs[start:min(start+ecrBatch, len(imgs))], platforms)
		if err != nil {
			return err
		}
		unresolved += n
	}
	var digests []string
	seen := map[string]bool{}
	for _, ds := range platforms {
		for _, d := range ds {
			if !seen[d] {
				seen[d] = true
				digests = append(digests, d)
			}
		}
	}
	sortStrings(digests)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.report.Coverage.UnresolvedImages += unresolved
	for img, ds := range platforms {
		img.platforms = ds
		for _, d := range ds {
			pk := platformKey{k.registry, k.repo, d}
			s.platforms[pk] = append(s.platforms[pk], img)
		}
	}
	for _, d := range digests {
		s.status[platformKey{k.registry, k.repo, d}] = statusNotCovered
	}
	return nil
}

// resolveBatch looks up one batch of a repository's images, adding their
// platform digests to platforms; it returns how many could not be resolved.
func (s *scan) resolveBatch(ctx context.Context, k repoKey, imgs []*runningImage, platforms map[*runningImage][]string) (int, error) {
	byDigest := map[string]*runningImage{}
	ids := make([]ecrtypes.ImageIdentifier, 0, len(imgs))
	for _, img := range imgs {
		byDigest[img.digest] = img
		ids = append(ids, ecrtypes.ImageIdentifier{ImageDigest: aws.String(img.digest)})
	}
	if err := s.spend(ctx); err != nil {
		return 0, err
	}
	s.countCall(&s.report.ECRCalls)
	out, err := s.ecr.BatchGetImage(ctx, &ecr.BatchGetImageInput{
		RegistryId: aws.String(k.registry), RepositoryName: aws.String(k.repo),
		ImageIds: ids, AcceptedMediaTypes: manifestMediaTypes,
	})
	if err != nil {
		if s.budgetErr(ctx, err) {
			return 0, err
		}
		// Typically another account's registry we can't read, or a
		// deleted repository: count as unresolved, keep going.
		return len(imgs), nil
	}
	resolved := 0
	for _, im := range out.Images {
		img := byDigest[aws.ToString(im.ImageId.ImageDigest)]
		if img == nil || platforms[img] != nil {
			continue
		}
		resolved++
		platforms[img] = platformDigests(img.digest, aws.ToString(im.ImageManifest))
	}
	return len(imgs) - resolved, nil
}

// platformDigests returns an image index's runnable platform manifests
// (skipping attestation manifests, platform "unknown"), or the digest
// itself for a single-platform manifest.
func platformDigests(digest, manifest string) []string {
	var m struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform *struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if json.Unmarshal([]byte(manifest), &m) != nil || len(m.Manifests) == 0 {
		return []string{digest}
	}
	var out []string
	for _, c := range m.Manifests {
		if c.Platform != nil && c.Platform.Architecture != "" && c.Platform.Architecture != "unknown" {
			out = append(out, c.Digest)
		}
	}
	if len(out) == 0 {
		return []string{digest}
	}
	return out
}
