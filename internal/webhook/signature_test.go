package webhook

import (
	"testing"
)

func TestVerifier_Verify(t *testing.T) {
	secret := "test-secret"
	verifier := NewVerifier(secret)
	payload := []byte(`{"type":"pv_resize","payload":{"namespace":"default"}}`)

	// Generate a valid signature
	validSig := verifier.Sign(payload)

	tests := []struct {
		name      string
		signature string
		payload   []byte
		wantErr   error
	}{
		{
			name:      "valid signature",
			signature: validSig,
			payload:   payload,
			wantErr:   nil,
		},
		{
			name:      "empty signature",
			signature: "",
			payload:   payload,
			wantErr:   ErrMissingSignature,
		},
		{
			name:      "missing prefix",
			signature: "abc123",
			payload:   payload,
			wantErr:   ErrInvalidSignatureFormat,
		},
		{
			name:      "invalid hex",
			signature: "sha256=notvalidhex!!!",
			payload:   payload,
			wantErr:   ErrInvalidSignatureFormat,
		},
		{
			name:      "wrong signature",
			signature: "sha256=0000000000000000000000000000000000000000000000000000000000000000",
			payload:   payload,
			wantErr:   ErrInvalidSignature,
		},
		{
			name:      "modified payload",
			signature: validSig,
			payload:   []byte(`{"type":"different"}`),
			wantErr:   ErrInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.Verify(tt.signature, tt.payload)
			if err != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifier_Sign(t *testing.T) {
	secret := "test-secret"
	verifier := NewVerifier(secret)
	payload := []byte(`{"test":"data"}`)

	sig := verifier.Sign(payload)

	// Check format
	if len(sig) < 7 || sig[:7] != "sha256=" {
		t.Errorf("Sign() should return signature with sha256= prefix, got %s", sig)
	}

	// Verify the signature we just created
	if err := verifier.Verify(sig, payload); err != nil {
		t.Errorf("Sign() created invalid signature: %v", err)
	}
}

func TestVerifier_DifferentSecrets(t *testing.T) {
	payload := []byte(`{"test":"data"}`)

	verifier1 := NewVerifier("secret1")
	verifier2 := NewVerifier("secret2")

	sig := verifier1.Sign(payload)

	// Same secret should verify
	if err := verifier1.Verify(sig, payload); err != nil {
		t.Errorf("same secret should verify: %v", err)
	}

	// Different secret should fail
	if err := verifier2.Verify(sig, payload); err != ErrInvalidSignature {
		t.Errorf("different secret should fail with ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifier_EmptyPayload(t *testing.T) {
	verifier := NewVerifier("secret")
	payload := []byte{}

	sig := verifier.Sign(payload)
	if err := verifier.Verify(sig, payload); err != nil {
		t.Errorf("empty payload should verify: %v", err)
	}
}

// BenchmarkVerify tests performance of signature verification.
func BenchmarkVerify(b *testing.B) {
	verifier := NewVerifier("test-secret")
	payload := []byte(`{"type":"pv_resize","payload":{"namespace":"default","pvc_name":"data","new_size":"20Gi"}}`)
	sig := verifier.Sign(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.Verify(sig, payload)
	}
}
