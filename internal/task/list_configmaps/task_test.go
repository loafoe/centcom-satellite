package list_configmaps

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTask_Name(t *testing.T) {
	assert.Equal(t, "list_configmaps", New(fake.NewSimpleClientset()).Name())
}

func TestTask_Execute_EmptyCluster(t *testing.T) {
	task := New(fake.NewSimpleClientset())
	result, err := task.Execute(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	details, ok := result.Details.(*ConfigMapList)
	require.True(t, ok, "expected ConfigMapList in Details")
	assert.Equal(t, 0, details.Total)
}

func TestTask_Execute_MetadataOnly_NoValues(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-config",
			Namespace: "kube-system",
			Labels:    map[string]string{"app": "cilium"},
		},
		Data: map[string]string{
			"enable-wireguard": "true",
			"cluster-name":     "prod-eu",
		},
		BinaryData: map[string][]byte{
			"cert.der": []byte{0x01, 0x02, 0x03, 0x04},
		},
	}
	task := New(fake.NewSimpleClientset(cm))

	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"kube-system"}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	details := result.Details.(*ConfigMapList)
	require.Equal(t, 1, details.Total)
	info := details.ConfigMaps[0]

	// Keys are present and sorted; data values are NOT exposed anywhere.
	assert.Equal(t, []string{"cert.der", "cluster-name", "enable-wireguard"}, info.Keys)
	assert.Equal(t, 4, info.DataSizes["enable-wireguard"]) // len("true")
	assert.Equal(t, 7, info.DataSizes["cluster-name"])     // len("prod-eu")
	assert.Equal(t, 4, info.DataSizes["cert.der"])         // 4 bytes binary
	assert.Equal(t, "cilium", info.Labels["app"])

	// Guard: the marshalled result must not contain any value content.
	raw, err := json.Marshal(details)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "true")
	assert.NotContains(t, string(raw), "prod-eu")
}

func TestTask_Execute_LabelSelector(t *testing.T) {
	matching := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default", Labels: map[string]string{"team": "infra"}},
		Data:       map[string]string{"k": "v"},
	}
	other := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "default", Labels: map[string]string{"team": "apps"}},
		Data:       map[string]string{"k": "v"},
	}
	task := New(fake.NewSimpleClientset(matching, other))

	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"default","label_selector":"team=infra"}`))
	require.NoError(t, err)

	details := result.Details.(*ConfigMapList)
	require.Equal(t, 1, details.Total)
	assert.Equal(t, "a", details.ConfigMaps[0].Name)
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	task := New(fake.NewSimpleClientset())
	result, err := task.Execute(context.Background(), json.RawMessage(`{not json`))
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid payload")
}
