package get_configmap

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
	assert.Equal(t, "get_configmap", New(fake.NewSimpleClientset()).Name())
}

func newCM() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-config", Namespace: "kube-system"},
		Data: map[string]string{
			"enable-wireguard": "true",
			"bearer-token":     "aB3xY9zQw7Lp2Km5Nv8Rt4Hs6Jd0Fg1",
		},
		BinaryData: map[string][]byte{
			"cert.der": {0x01, 0x02, 0x03},
		},
	}
}

func TestTask_Execute_RedactsButKeepsConfigFlag(t *testing.T) {
	task := New(fake.NewSimpleClientset(newCM()))
	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"kube-system","name":"cilium-config"}`))
	require.NoError(t, err)
	require.True(t, result.Success)

	d := result.Details.(*ConfigMapDetail)
	assert.Equal(t, "true", d.Data["enable-wireguard"])             // safe value preserved
	assert.Contains(t, d.Data["bearer-token"], "[REDACTED")         // secret masked
	assert.Contains(t, d.RedactedKeys, "bearer-token")
	assert.NotContains(t, d.RedactedKeys, "enable-wireguard")
	assert.Equal(t, []string{"cert.der"}, d.BinaryKeys)

	// The raw secret value must never appear in the marshalled output.
	raw, _ := json.Marshal(d)
	assert.NotContains(t, string(raw), "aB3xY9zQw7Lp2Km5Nv8Rt4Hs6Jd0Fg1")
}

func TestTask_Execute_KeyFilter(t *testing.T) {
	task := New(fake.NewSimpleClientset(newCM()))
	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"kube-system","name":"cilium-config","keys":["enable-wireguard"]}`))
	require.NoError(t, err)

	d := result.Details.(*ConfigMapDetail)
	assert.Len(t, d.Data, 1)
	assert.Equal(t, "true", d.Data["enable-wireguard"])
	_, present := d.Data["bearer-token"]
	assert.False(t, present, "filtered-out key must not be returned")
	assert.Empty(t, d.BinaryKeys, "binary key not in filter")
}

func TestTask_Execute_BinaryNeverReturnedAsValue(t *testing.T) {
	task := New(fake.NewSimpleClientset(newCM()))
	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"kube-system","name":"cilium-config"}`))
	require.NoError(t, err)

	d := result.Details.(*ConfigMapDetail)
	_, inData := d.Data["cert.der"]
	assert.False(t, inData, "binary key must not appear in Data")
	assert.Contains(t, d.BinaryKeys, "cert.der")
}

func TestTask_Execute_NotFound(t *testing.T) {
	task := New(fake.NewSimpleClientset())
	result, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"kube-system","name":"missing"}`))
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "not found")
}

func TestTask_Execute_RequiredParams(t *testing.T) {
	task := New(fake.NewSimpleClientset())

	r1, err := task.Execute(context.Background(), json.RawMessage(`{"name":"x"}`))
	require.NoError(t, err)
	assert.False(t, r1.Success)
	assert.Contains(t, r1.Error, "namespace is required")

	r2, err := task.Execute(context.Background(), json.RawMessage(`{"namespace":"x"}`))
	require.NoError(t, err)
	assert.False(t, r2.Success)
	assert.Contains(t, r2.Error, "name is required")
}

func TestTask_Execute_InvalidPayload(t *testing.T) {
	task := New(fake.NewSimpleClientset())
	result, err := task.Execute(context.Background(), json.RawMessage(`{bad`))
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid payload")
}
