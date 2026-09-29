package helm_application

import (
	"context"
	"encoding/json"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/loafoe/centcom-satellite/internal/task"
)

const DeleteTaskName = "helm_application_delete"

type DeleteTask struct{ dynamicClient dynamic.Interface }

func NewDelete(dynamicClient dynamic.Interface) *DeleteTask {
	return &DeleteTask{dynamicClient: dynamicClient}
}

func (t *DeleteTask) Name() string { return DeleteTaskName }

func (t *DeleteTask) Execute(ctx context.Context, payloadBytes json.RawMessage) (*task.Result, error) {
	var p struct{ APIVersion, Name, Namespace string }
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return task.NewErrorResult("invalid payload: " + err.Error()), nil
	}
	if p.APIVersion == "" || p.Name == "" || p.Namespace == "" {
		return task.NewErrorResult("apiVersion, name, and namespace are required"), nil
	}
	gv, err := schema.ParseGroupVersion(p.APIVersion)
	if err != nil {
		return task.NewErrorResult("invalid apiVersion: " + err.Error()), nil
	}
	client := t.dynamicClient.Resource(gv.WithResource(helmApplicationsResource)).Namespace(p.Namespace)

	if err := client.Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewSuccessResultWithDetails("already deleted", nil), nil
		}
		return nil, err
	}

	// A namespace-scoped composite with no finalizers deletes synchronously;
	// re-Get once to detect the "stuck behind a finalizer" case without an
	// unbounded wait loop.
	obj, err := client.Get(ctx, p.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return task.NewSuccessResultWithDetails("deleted", nil), nil
		}
		return nil, err
	}
	if len(obj.GetFinalizers()) > 0 {
		return nil, &StuckDeletingError{Name: p.Name, Finalizers: obj.GetFinalizers()}
	}
	return task.NewSuccessResultWithDetails("delete accepted, terminating", nil), nil
}
