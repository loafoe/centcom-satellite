package resourceaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestNew_SecretAlwaysDeniedEvenWithEmptyConfig(t *testing.T) {
	d := New(nil)
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "", Kind: "Secret"}))
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "", Kind: "secret"}), "kind match is case-insensitive")
}

func TestNew_DefaultIsOtherwisePermissive(t *testing.T) {
	d := New(nil)
	assert.False(t, d.IsDenied(schema.GroupKind{Group: "", Kind: "ConfigMap"}))
	assert.False(t, d.IsDenied(schema.GroupKind{Group: "apps", Kind: "Deployment"}))
	assert.False(t, d.IsDenied(schema.GroupKind{Group: "external-secrets.io", Kind: "SecretStore"}),
		"the denylist ships empty beyond Secret by design - operators opt specific kinds in")
}

func TestNew_ExtraEntriesAreDenied(t *testing.T) {
	extra := []schema.GroupKind{
		{Group: "external-secrets.io", Kind: "SecretStore"},
		{Group: "", Kind: "ServiceAccount"},
	}
	d := New(extra)
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "external-secrets.io", Kind: "SecretStore"}))
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "", Kind: "ServiceAccount"}))
	// A same-named kind in a DIFFERENT group must not be caught by an
	// unrelated denial - group+kind match, not kind-only.
	assert.False(t, d.IsDenied(schema.GroupKind{Group: "example.com", Kind: "ServiceAccount"}))
}

func TestNew_GroupAndKindMatchCaseInsensitively(t *testing.T) {
	d := New([]schema.GroupKind{{Group: "Cert-Manager.IO", Kind: "Certificate"}})
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "cert-manager.io", Kind: "certificate"}))
}

func TestParseGroupKindList_Empty(t *testing.T) {
	got, err := ParseGroupKindList("")
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = ParseGroupKindList("   ")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestParseGroupKindList_CoreAndNonCoreGroups(t *testing.T) {
	got, err := ParseGroupKindList("cert-manager.io/Certificate,/ServiceAccount,external-secrets.io/SecretStore")
	require.NoError(t, err)
	assert.Equal(t, []schema.GroupKind{
		{Group: "cert-manager.io", Kind: "Certificate"},
		{Group: "", Kind: "ServiceAccount"},
		{Group: "external-secrets.io", Kind: "SecretStore"},
	}, got)
}

func TestParseGroupKindList_WhitespaceAndTrailingCommasAreTolerated(t *testing.T) {
	got, err := ParseGroupKindList(" /ServiceAccount , cert-manager.io/Certificate ,")
	require.NoError(t, err)
	assert.Equal(t, []schema.GroupKind{
		{Group: "", Kind: "ServiceAccount"},
		{Group: "cert-manager.io", Kind: "Certificate"},
	}, got)
}

func TestParseGroupKindList_MissingSlashIsAnError(t *testing.T) {
	_, err := ParseGroupKindList("ServiceAccount")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected group/Kind")
}

func TestParseGroupKindList_EmptyKindIsAnError(t *testing.T) {
	_, err := ParseGroupKindList("cert-manager.io/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kind is required")
}

func TestParseGroupKindList_FeedsDirectlyIntoNew(t *testing.T) {
	extra, err := ParseGroupKindList("external-secrets.io/SecretStore,/ServiceAccount")
	require.NoError(t, err)
	d := New(extra)
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "external-secrets.io", Kind: "SecretStore"}))
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "", Kind: "ServiceAccount"}))
	assert.True(t, d.IsDenied(schema.GroupKind{Group: "", Kind: "Secret"}), "the non-negotiable floor still applies")
}
