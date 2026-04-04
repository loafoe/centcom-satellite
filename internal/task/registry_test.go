package task

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// mockTask is a test implementation of Task.
type mockTask struct {
	name   string
	result *Result
	err    error
}

func (m *mockTask) Name() string {
	return m.name
}

func (m *mockTask) Execute(_ context.Context, _ json.RawMessage) (*Result, error) {
	return m.result, m.err
}

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry()
	task := &mockTask{name: "test"}

	reg.Register(task)

	got, ok := reg.Get("test")
	if !ok {
		t.Fatal("task not found after registration")
	}
	if got.Name() != "test" {
		t.Errorf("got name %q, want %q", got.Name(), "test")
	}
}

func TestRegistry_RegisterOverwrite(t *testing.T) {
	reg := NewRegistry()

	task1 := &mockTask{name: "test", result: NewSuccessResult("first")}
	task2 := &mockTask{name: "test", result: NewSuccessResult("second")}

	reg.Register(task1)
	reg.Register(task2)

	got, _ := reg.Get("test")
	result, _ := got.Execute(context.Background(), nil)

	if result.Message != "second" {
		t.Errorf("expected task to be overwritten, got message %q", result.Message)
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	reg := NewRegistry()

	_, ok := reg.Get("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent task")
	}
}

func TestRegistry_List(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockTask{name: "task1"})
	reg.Register(&mockTask{name: "task2"})

	names := reg.List()

	if len(names) != 2 {
		t.Errorf("expected 2 tasks, got %d", len(names))
	}

	// Check both names are present (order not guaranteed)
	found := make(map[string]bool)
	for _, name := range names {
		found[name] = true
	}

	if !found["task1"] || !found["task2"] {
		t.Errorf("missing expected tasks: %v", names)
	}
}

func TestRegistry_Execute(t *testing.T) {
	reg := NewRegistry()
	expectedResult := NewSuccessResult("done")
	reg.Register(&mockTask{name: "test", result: expectedResult})

	result, err := reg.Execute(context.Background(), Request{
		Type:    "test",
		Payload: json.RawMessage(`{}`),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Success {
		t.Error("expected success")
	}

	if result.Message != "done" {
		t.Errorf("got message %q, want %q", result.Message, "done")
	}
}

func TestRegistry_Execute_EmptyType(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.Execute(context.Background(), Request{Type: ""})

	if !errors.Is(err, ErrEmptyTaskType) {
		t.Errorf("expected ErrEmptyTaskType, got %v", err)
	}
}

func TestRegistry_Execute_NotFound(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.Execute(context.Background(), Request{Type: "unknown"})

	if !errors.Is(err, ErrTaskNotFound) {
		t.Errorf("expected ErrTaskNotFound, got %v", err)
	}
}

func TestRegistry_Execute_TaskError(t *testing.T) {
	reg := NewRegistry()
	expectedErr := errors.New("task failed")
	reg.Register(&mockTask{name: "failing", err: expectedErr})

	_, err := reg.Execute(context.Background(), Request{Type: "failing"})

	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid request",
			data:    []byte(`{"type":"pv_resize","payload":{"namespace":"default"}}`),
			wantErr: false,
		},
		{
			name:    "empty payload",
			data:    []byte(`{"type":"test"}`),
			wantErr: false,
		},
		{
			name:    "invalid json",
			data:    []byte(`{invalid}`),
			wantErr: true,
		},
		{
			name:    "empty input",
			data:    []byte(``),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseRequest(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if req == nil {
				t.Error("expected request, got nil")
			}
		})
	}
}

func TestNewSuccessResult(t *testing.T) {
	result := NewSuccessResult("operation completed")

	if !result.Success {
		t.Error("expected Success to be true")
	}

	if result.Message != "operation completed" {
		t.Errorf("got message %q, want %q", result.Message, "operation completed")
	}

	if result.Error != "" {
		t.Errorf("expected empty error, got %q", result.Error)
	}
}

func TestNewErrorResult(t *testing.T) {
	result := NewErrorResult("something went wrong")

	if result.Success {
		t.Error("expected Success to be false")
	}

	if result.Error != "something went wrong" {
		t.Errorf("got error %q, want %q", result.Error, "something went wrong")
	}

	if result.Message != "" {
		t.Errorf("expected empty message, got %q", result.Message)
	}
}
