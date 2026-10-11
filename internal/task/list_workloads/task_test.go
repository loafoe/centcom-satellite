package list_workloads

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func TestTask_Execute_CronJobs(t *testing.T) {
	lastSchedule := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	lastSuccessful := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	cronjob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "nightly-backup",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-48 * time.Hour)),
		},
		Spec: batchv1.CronJobSpec{
			Schedule: "0 2 * * *",
			Suspend:  ptr.To(false),
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{Name: "backup", Image: "backup:v1"},
							},
						},
					},
				},
			},
		},
		Status: batchv1.CronJobStatus{
			LastScheduleTime:   &lastSchedule,
			LastSuccessfulTime: &lastSuccessful,
			Active:             []corev1.ObjectReference{{Name: "nightly-backup-123"}},
		},
	}

	clientset := fake.NewSimpleClientset(cronjob)
	task := New(clientset)

	payload, _ := json.Marshal(Payload{Kind: "cronjob"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*WorkloadList)
	require.True(t, ok)
	require.Len(t, details.Workloads, 1)

	w := details.Workloads[0]
	assert.Equal(t, "nightly-backup", w.Name)
	assert.Equal(t, "default", w.Namespace)
	assert.Equal(t, "CronJob", w.Kind)
	assert.Equal(t, "0 2 * * *", w.Schedule)
	assert.False(t, w.Suspended)
	assert.Equal(t, []string{"backup:v1"}, w.Images)
	assert.Equal(t, int32(1), w.ActiveJobs)
	assert.Equal(t, lastSchedule.Format(time.RFC3339), w.LastScheduleTime)
	assert.Equal(t, lastSuccessful.Format(time.RFC3339), w.LastSuccessfulTime)
}

func TestTask_Execute_CronJobs_Suspended(t *testing.T) {
	cronjob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "paused-job", Namespace: "default"},
		Spec: batchv1.CronJobSpec{
			Schedule: "*/5 * * * *",
			Suspend:  ptr.To(true),
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "c", Image: "img:v1"}},
						},
					},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(cronjob)
	task := New(clientset)

	payload, _ := json.Marshal(Payload{Kind: "cronjob"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*WorkloadList)
	require.True(t, ok)
	require.Len(t, details.Workloads, 1)
	assert.True(t, details.Workloads[0].Suspended)
	assert.Equal(t, "", details.Workloads[0].LastScheduleTime)
	assert.Equal(t, int32(0), details.Workloads[0].ActiveJobs)
}

func TestTask_Execute_Jobs(t *testing.T) {
	startTime := metav1.NewTime(time.Now().Add(-10 * time.Minute))
	completionTime := metav1.NewTime(time.Now().Add(-9 * time.Minute))
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "nightly-backup-28391",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "CronJob", Name: "nightly-backup"},
			},
		},
		Spec: batchv1.JobSpec{
			Completions: ptr.To(int32(1)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "backup", Image: "backup:v1"}},
				},
			},
		},
		Status: batchv1.JobStatus{
			Succeeded:      1,
			StartTime:      &startTime,
			CompletionTime: &completionTime,
		},
	}

	clientset := fake.NewSimpleClientset(job)
	task := New(clientset)

	payload, _ := json.Marshal(Payload{Kind: "job"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	details, ok := result.Details.(*WorkloadList)
	require.True(t, ok)
	require.Len(t, details.Workloads, 1)

	w := details.Workloads[0]
	assert.Equal(t, "nightly-backup-28391", w.Name)
	assert.Equal(t, "Job", w.Kind)
	assert.Equal(t, "nightly-backup", w.OwnerCronJob)
	assert.Equal(t, int32(1), w.JobCompletions)
	assert.Equal(t, int32(1), w.JobSucceeded)
	assert.Equal(t, int32(0), w.JobFailed)
	assert.Equal(t, startTime.Format(time.RFC3339), w.JobStartTime)
	assert.Equal(t, completionTime.Format(time.RFC3339), w.JobCompletionTime)
}

func TestTask_Execute_Jobs_Standalone_NoOwner(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "one-off-migration", Namespace: "default"},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img:v1"}}},
			},
		},
		Status: batchv1.JobStatus{Active: 1},
	}

	clientset := fake.NewSimpleClientset(job)
	task := New(clientset)

	payload, _ := json.Marshal(Payload{Kind: "job"})
	result, err := task.Execute(context.Background(), payload)
	require.NoError(t, err)

	details, ok := result.Details.(*WorkloadList)
	require.True(t, ok)
	require.Len(t, details.Workloads, 1)
	assert.Equal(t, "", details.Workloads[0].OwnerCronJob)
	assert.Equal(t, int32(1), details.Workloads[0].JobActive)
	// Default completions is 1 when Spec.Completions is unset.
	assert.Equal(t, int32(1), details.Workloads[0].JobCompletions)
}

func TestTask_Execute_All_ExcludesJobs(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "j", Namespace: "default"},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img:v1"}}},
			},
		},
	}

	clientset := fake.NewSimpleClientset(job)
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)

	details, ok := result.Details.(*WorkloadList)
	require.True(t, ok)
	assert.Empty(t, details.Workloads, "kind=all must not include Jobs - clusters can accumulate many completed Jobs")
}

func TestTask_Execute_All_IncludesCronJobs(t *testing.T) {
	cronjob := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "cj", Namespace: "default"},
		Spec: batchv1.CronJobSpec{
			Schedule: "@daily",
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img:v1"}}},
					},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(cronjob)
	task := New(clientset)

	result, err := task.Execute(context.Background(), json.RawMessage("{}"))
	require.NoError(t, err)

	details, ok := result.Details.(*WorkloadList)
	require.True(t, ok)
	require.Len(t, details.Workloads, 1)
	assert.Equal(t, "CronJob", details.Workloads[0].Kind)
}

// TestConvertPodAffinityTerm_MatchLabelsOrderIsDeterministic is the
// regression test for a real production incident: centcom's workload
// change-timeline falsely reported a spec change on every single poll for
// any workload with a multi-key matchLabels pod(anti)affinity selector,
// because this function appended straight from a `range` over
// LabelSelector.MatchLabels (a map) - Go map iteration order is
// randomized per call, so the resulting []SelectorRequirement had a
// different order every time even though MatchLabels itself never
// changed. 50 repeated calls on the same multi-key input is enough to
// almost certainly surface the bug if it regresses (3 keys = 6 possible
// orderings; the odds of 50 random draws all landing on the same one by
// chance are negligible).
func TestConvertPodAffinityTerm_MatchLabelsOrderIsDeterministic(t *testing.T) {
	term := corev1.PodAffinityTerm{
		TopologyKey: "kubernetes.io/hostname",
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "checkout", "tier": "backend", "env": "prod"},
		},
	}
	first := convertPodAffinityTerm(term)
	for i := 0; i < 50; i++ {
		got := convertPodAffinityTerm(term)
		require.Equal(t, first.LabelSelector, got.LabelSelector, "iteration %d produced a different order", i)
	}
	keys := make([]string, len(first.LabelSelector))
	for i, r := range first.LabelSelector {
		keys[i] = r.Key
	}
	assert.Equal(t, []string{"app", "env", "tier"}, keys, "expected alphabetical key order")
}

func TestExtractTopologySpreadConstraints_MatchLabelsOrderIsDeterministic(t *testing.T) {
	constraints := []corev1.TopologySpreadConstraint{
		{
			MaxSkew:     1,
			TopologyKey: "topology.kubernetes.io/zone",
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "checkout", "tier": "backend", "env": "prod"},
			},
		},
	}
	first := extractTopologySpreadConstraints(constraints)
	for i := 0; i < 50; i++ {
		got := extractTopologySpreadConstraints(constraints)
		require.Equal(t, first, got, "iteration %d produced a different order", i)
	}
}

func TestExtractConfigRefs_VolumesEnvFromAndValueFrom(t *testing.T) {
	spec := corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name: "cfg",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
					},
				},
			},
			{
				Name: "secret-vol",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: "app-tls"},
				},
			},
			{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "app-data"},
				},
			},
			{
				Name: "proj",
				VolumeSource: corev1.VolumeSource{
					Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{
							{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "proj-config"}}},
							{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "proj-secret"}}},
						},
					},
				},
			},
		},
		InitContainers: []corev1.Container{
			{
				Name: "init",
				EnvFrom: []corev1.EnvFromSource{
					{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "init-config"}}},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name: "main",
				EnvFrom: []corev1.EnvFromSource{
					{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "env-secret"}}},
				},
				Env: []corev1.EnvVar{
					{
						Name: "DB_PASSWORD",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "app-tls"}, Key: "password"},
						},
					},
					{
						Name: "FEATURE_FLAG",
						ValueFrom: &corev1.EnvVarSource{
							ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}, Key: "flag"},
						},
					},
					{Name: "PLAIN", Value: "no-ref-here"},
				},
			},
		},
	}

	cmRefs, secretRefs, pvcRefs := extractConfigRefs(spec)

	assert.Equal(t, []string{"app-config", "init-config", "proj-config"}, cmRefs)
	assert.Equal(t, []string{"app-tls", "env-secret", "proj-secret"}, secretRefs)
	assert.Equal(t, []string{"app-data"}, pvcRefs)
}

func TestExtractConfigRefs_EmptySpecReturnsNilSlices(t *testing.T) {
	cmRefs, secretRefs, pvcRefs := extractConfigRefs(corev1.PodSpec{})
	assert.Nil(t, cmRefs)
	assert.Nil(t, secretRefs)
	assert.Nil(t, pvcRefs)
}
