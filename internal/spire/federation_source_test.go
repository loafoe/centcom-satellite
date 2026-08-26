package spire

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// testBundleServer serves a real, marshaled SPIFFE bundle (one JWT
// authority) for the given trust domain, so tests exercise the actual
// spiffebundle.Read parse path FetchBundle uses, not a hand-rolled stand-in.
func testBundleServer(t *testing.T, td spiffeid.TrustDomain) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	bundle := spiffebundle.FromJWTAuthorities(td, map[string]crypto.PublicKey{"kid1": &key.PublicKey})
	body, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
}

func TestStartFederationJWTSource_FetchesInitialBundle(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	srv := testBundleServer(t, td)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := JWTConfig{
		FederationBundleEndpoints: map[string]string{"example.org": srv.URL},
	}
	source, err := startFederationJWTSource(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jb, err := source.GetJWTBundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("unexpected error getting JWT bundle: %v", err)
	}
	if jb == nil {
		t.Fatal("expected non-nil JWT bundle")
	}
}

func TestStartFederationJWTSource_FailsFastOnUnreachableEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := JWTConfig{
		// Port 1 is reserved and never listens — connection refused, fast.
		FederationBundleEndpoints: map[string]string{"example.org": "http://127.0.0.1:1/nope"},
	}
	if _, err := startFederationJWTSource(ctx, cfg); err == nil {
		t.Fatal("expected error when the federation endpoint is unreachable")
	}
}

func TestStartFederationJWTSource_InvalidTrustDomain(t *testing.T) {
	cfg := JWTConfig{
		FederationBundleEndpoints: map[string]string{"not a trust domain!!": "http://example.org/bundle"},
	}
	if _, err := startFederationJWTSource(context.Background(), cfg); err == nil {
		t.Fatal("expected error for an invalid trust domain name")
	}
}

func TestFederationJWTSource_GetJWTBundleForTrustDomain_NotYetFetched(t *testing.T) {
	source := newFederationJWTSource()
	_, err := source.GetJWTBundleForTrustDomain(spiffeid.RequireTrustDomainFromString("example.org"))
	if err == nil {
		t.Fatal("expected error when no bundle has been fetched for this trust domain yet")
	}
}
