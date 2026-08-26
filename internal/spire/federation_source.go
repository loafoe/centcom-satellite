package spire

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// federationJWTSource implements jwtbundle.Source by fetching and keeping
// live-updated one SPIFFE bundle per trust domain from a SPIFFE Federation
// Bundle Endpoint — no local SPIRE Agent / Workload API required. It is a
// drop-in alternative to workloadapi.JWTSource: jwtsvid.ParseAndValidate
// (via Client.ValidateJWTToken) calls the jwtbundle.Source interface, not
// this concrete type, so swapping between the two requires no change to
// validation logic.
type federationJWTSource struct {
	mu      sync.RWMutex
	bundles map[string]*spiffebundle.Bundle // trust domain name -> latest bundle
}

func newFederationJWTSource() *federationJWTSource {
	return &federationJWTSource{bundles: make(map[string]*spiffebundle.Bundle)}
}

// GetJWTBundleForTrustDomain implements jwtbundle.Source.
func (f *federationJWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	f.mu.RLock()
	bundle, ok := f.bundles[trustDomain.Name()]
	f.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no federation bundle fetched yet for trust domain %q", trustDomain.Name())
	}
	return bundle.GetJWTBundleForTrustDomain(trustDomain)
}

func (f *federationJWTSource) set(trustDomainName string, bundle *spiffebundle.Bundle) {
	f.mu.Lock()
	f.bundles[trustDomainName] = bundle
	f.mu.Unlock()
}

// federationBundleWatcher adapts federation.WatchBundle's callbacks for one
// trust domain into federationJWTSource. OnError logs and keeps serving the
// last-known-good bundle rather than tearing anything down — a transient
// endpoint outage must not blank out already-trusted key material, matching
// this codebase's "an outage never blanks known-good state" posture used
// elsewhere (e.g. cross-account AssumeRole's persistGeo).
type federationBundleWatcher struct {
	trustDomain spiffeid.TrustDomain
	source      *federationJWTSource
}

func (w *federationBundleWatcher) NextRefresh(refreshHint time.Duration) time.Duration {
	if refreshHint > 0 {
		return refreshHint
	}
	return 5 * time.Minute
}

func (w *federationBundleWatcher) OnUpdate(bundle *spiffebundle.Bundle) {
	w.source.set(w.trustDomain.Name(), bundle)
	slog.Info("federation bundle updated", "trust_domain", w.trustDomain.Name())
}

func (w *federationBundleWatcher) OnError(err error) {
	slog.Warn("federation bundle fetch failed, keeping last-known-good bundle",
		"trust_domain", w.trustDomain.Name(), "error", err)
}

// startFederationJWTSource performs one synchronous fetch per configured
// trust domain — failing fast on an unreachable endpoint or an invalid
// trust domain name, matching AssumeRole.Init's posture of surfacing
// misconfiguration at startup rather than on the first caller's request —
// then starts one background watcher goroutine per trust domain to keep
// the bundle live-updated for as long as ctx isn't cancelled.
func startFederationJWTSource(ctx context.Context, cfg JWTConfig) (*federationJWTSource, error) {
	source := newFederationJWTSource()

	var fetchOpts []federation.FetchOption
	if cfg.FederationCABundlePath != "" {
		pem, err := os.ReadFile(cfg.FederationCABundlePath)
		if err != nil {
			return nil, fmt.Errorf("read federation CA bundle %s: %w", cfg.FederationCABundlePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in federation CA bundle %s", cfg.FederationCABundlePath)
		}
		fetchOpts = append(fetchOpts, federation.WithWebPKIRoots(pool))
	}

	for tdName, url := range cfg.FederationBundleEndpoints {
		td, err := spiffeid.TrustDomainFromString(tdName)
		if err != nil {
			return nil, fmt.Errorf("invalid federation trust domain %q: %w", tdName, err)
		}

		bundle, err := federation.FetchBundle(ctx, td, url, fetchOpts...)
		if err != nil {
			return nil, fmt.Errorf("initial federation bundle fetch for %q from %s: %w", tdName, url, err)
		}
		source.set(tdName, bundle)
		slog.Info("fetched initial federation bundle", "trust_domain", tdName, "url", url)

		go func(td spiffeid.TrustDomain, url string) {
			watcher := &federationBundleWatcher{trustDomain: td, source: source}
			if err := federation.WatchBundle(ctx, td, url, watcher, fetchOpts...); err != nil && ctx.Err() == nil {
				slog.Error("federation bundle watcher stopped unexpectedly", "trust_domain", td.Name(), "error", err)
			}
		}(td, url)
	}

	return source, nil
}
