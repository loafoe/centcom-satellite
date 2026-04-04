package pv_resize

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func boolPtr(b bool) *bool {
	return &b
}

func strPtr(s string) *string {
	return &s
}

func TestTask_Name(t *testing.T) {
	task := New(fake.NewSimpleClientset())
	if task.Name() != TaskName {
		t.Errorf("expected %q, got %q", TaskName, task.Name())
	}
}

func TestTask_Execute(t *testing.T) {
	tests := []struct {
		name        string
		payload     interface{}
		objects     []runtime.Object
		wantSuccess bool
		wantError   bool
		wantErrMsg  string
	}{
		{
			name: "successful resize",
			payload: Payload{
				Namespace: "default",
				PVCName:   "test-pvc",
				NewSize:   "20Gi",
			},
			objects: []runtime.Object{
				&corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pvc",
						Namespace: "default",
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						StorageClassName: strPtr("standard"),
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse("10Gi"),
							},
						},
					},
				},
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "standard",
					},
					AllowVolumeExpansion: boolPtr(true),
				},
			},
			wantSuccess: true,
		},
		{
			name:        "empty payload",
			payload:     nil,
			wantSuccess: false,
			wantErrMsg:  "invalid payload",
		},
		{
			name:        "missing namespace",
			payload:     Payload{PVCName: "test", NewSize: "20Gi"},
			wantSuccess: false,
			wantErrMsg:  "namespace is required",
		},
		{
			name:        "missing pvc name",
			payload:     Payload{Namespace: "default", NewSize: "20Gi"},
			wantSuccess: false,
			wantErrMsg:  "pvc_name is required",
		},
		{
			name:        "missing new size",
			payload:     Payload{Namespace: "default", PVCName: "test"},
			wantSuccess: false,
			wantErrMsg:  "new_size is required",
		},
		{
			name: "invalid size format",
			payload: Payload{
				Namespace: "default",
				PVCName:   "test",
				NewSize:   "invalid",
			},
			wantSuccess: false,
			wantErrMsg:  "invalid size format",
		},
		{
			name: "pvc not found",
			payload: Payload{
				Namespace: "default",
				PVCName:   "nonexistent",
				NewSize:   "20Gi",
			},
			objects:     []runtime.Object{},
			wantSuccess: false,
			wantErrMsg:  "PVC not found",
		},
		{
			name: "expansion not allowed",
			payload: Payload{
				Namespace: "default",
				PVCName:   "test-pvc",
				NewSize:   "20Gi",
			},
			objects: []runtime.Object{
				&corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pvc",
						Namespace: "default",
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						StorageClassName: strPtr("no-expand"),
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse("10Gi"),
							},
						},
					},
				},
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "no-expand",
					},
					AllowVolumeExpansion: boolPtr(false),
				},
			},
			wantSuccess: false,
			wantErrMsg:  "storage class does not allow volume expansion",
		},
		{
			name: "size must increase",
			payload: Payload{
				Namespace: "default",
				PVCName:   "test-pvc",
				NewSize:   "5Gi",
			},
			objects: []runtime.Object{
				&corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pvc",
						Namespace: "default",
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						StorageClassName: strPtr("standard"),
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse("10Gi"),
							},
						},
					},
				},
				&storagev1.StorageClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "standard",
					},
					AllowVolumeExpansion: boolPtr(true),
				},
			},
			wantSuccess: false,
			wantErrMsg:  "new size must be larger than current size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset(tt.objects...)
			task := New(clientset)

			var rawPayload json.RawMessage
			if tt.payload != nil {
				data, _ := json.Marshal(tt.payload)
				rawPayload = data
			}

			result, err := task.Execute(context.Background(), rawPayload)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Success != tt.wantSuccess {
				t.Errorf("expected success=%v, got %v (error: %s)", tt.wantSuccess, result.Success, result.Error)
			}

			if tt.wantErrMsg != "" && result.Error == "" {
				t.Errorf("expected error message containing %q", tt.wantErrMsg)
			}

			if tt.wantErrMsg != "" && result.Error != "" {
				if !contains(result.Error, tt.wantErrMsg) {
					t.Errorf("error %q should contain %q", result.Error, tt.wantErrMsg)
				}
			}
		})
	}
}

func TestTask_Execute_UpdateError(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pvc",
				Namespace: "default",
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				StorageClassName: strPtr("standard"),
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("10Gi"),
					},
				},
			},
		},
		&storagev1.StorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "standard",
			},
			AllowVolumeExpansion: boolPtr(true),
		},
	)

	// Inject an error on update
	clientset.PrependReactor("update", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("update failed")
	})

	task := New(clientset)
	payload, _ := json.Marshal(Payload{
		Namespace: "default",
		PVCName:   "test-pvc",
		NewSize:   "20Gi",
	})

	_, err := task.Execute(context.Background(), payload)
	if err == nil {
		t.Error("expected error from update failure")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestTask_Execute_WithWait(t *testing.T) {
	// Create PVC with initial size
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pvc",
			Namespace: "default",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: strPtr("standard"),
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
		},
	}

	sc := &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard",
		},
		AllowVolumeExpansion: boolPtr(true),
	}

	clientset := fake.NewSimpleClientset(pvc, sc)

	// Simulate resize completion after a few gets
	var getCount atomic.Int32
	clientset.PrependReactor("get", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
		count := getCount.Add(1)
		if count >= 2 {
			// Return PVC with updated capacity
			return true, &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "default",
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					StorageClassName: strPtr("standard"),
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("20Gi"),
						},
					},
				},
				Status: corev1.PersistentVolumeClaimStatus{
					Capacity: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("20Gi"),
					},
				},
			}, nil
		}
		return false, nil, nil
	})

	task := New(clientset)
	payload, _ := json.Marshal(Payload{
		Namespace: "default",
		PVCName:   "test-pvc",
		NewSize:   "20Gi",
		Wait:      true,
		Timeout:   "10s",
	})

	result, err := task.Execute(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success, got error: %s", result.Error)
	}

	if result.Details == nil {
		t.Error("expected details in result")
	}

	details, ok := result.Details.(ResizeDetails)
	if !ok {
		t.Errorf("expected ResizeDetails, got %T", result.Details)
	}

	if details.FinalSize != "20Gi" {
		t.Errorf("expected final size 20Gi, got %s", details.FinalSize)
	}

	if details.Duration == "" {
		t.Error("expected duration in details")
	}
}

func TestTask_Execute_WaitTimeout(t *testing.T) {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pvc",
			Namespace: "default",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: strPtr("standard"),
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("10Gi"),
			},
		},
	}

	sc := &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard",
		},
		AllowVolumeExpansion: boolPtr(true),
	}

	clientset := fake.NewSimpleClientset(pvc, sc)

	// Never update the capacity - will cause timeout
	clientset.PrependReactor("get", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, pvc, nil
	})

	task := New(clientset)
	payload, _ := json.Marshal(Payload{
		Namespace: "default",
		PVCName:   "test-pvc",
		NewSize:   "20Gi",
		Wait:      true,
		Timeout:   "3s", // Short timeout for test
	})

	start := time.Now()
	result, err := task.Execute(context.Background(), payload)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Success {
		t.Error("expected failure due to timeout")
	}

	if !contains(result.Error, "timeout") {
		t.Errorf("expected timeout error, got: %s", result.Error)
	}

	// Should have taken at least close to the timeout
	if elapsed < 2*time.Second {
		t.Errorf("expected to wait for timeout, but only waited %v", elapsed)
	}
}

func TestTask_Execute_InvalidTimeout(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	task := New(clientset)

	payload, _ := json.Marshal(Payload{
		Namespace: "default",
		PVCName:   "test-pvc",
		NewSize:   "20Gi",
		Wait:      true,
		Timeout:   "invalid",
	})

	result, err := task.Execute(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Success {
		t.Error("expected failure due to invalid timeout")
	}

	if !contains(result.Error, "invalid timeout format") {
		t.Errorf("expected invalid timeout error, got: %s", result.Error)
	}
}
