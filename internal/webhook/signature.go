// Package webhook provides webhook signature verification.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// SignatureHeader is the HTTP header containing the webhook signature.
	SignatureHeader = "X-Grafana-Alertmanager-Signature"

	// signaturePrefix is the prefix for the signature value.
	signaturePrefix = "sha256="
)

var (
	// ErrMissingSignature is returned when the signature header is missing.
	ErrMissingSignature = errors.New("missing signature header")

	// ErrInvalidSignatureFormat is returned when the signature format is invalid.
	ErrInvalidSignatureFormat = errors.New("invalid signature format")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")
)

// Verifier verifies webhook signatures using HMAC-SHA256.
type Verifier struct {
	secret []byte
}

// NewVerifier creates a new signature verifier with the given secret.
func NewVerifier(secret string) *Verifier {
	return &Verifier{
		secret: []byte(secret),
	}
}

// Verify checks if the signature is valid for the given payload.
// The signature should be in the format "sha256=<hex-encoded-hmac>".
func (v *Verifier) Verify(signature string, payload []byte) error {
	if signature == "" {
		return ErrMissingSignature
	}

	if !strings.HasPrefix(signature, signaturePrefix) {
		return ErrInvalidSignatureFormat
	}

	providedSig := strings.TrimPrefix(signature, signaturePrefix)
	providedSigBytes, err := hex.DecodeString(providedSig)
	if err != nil {
		return ErrInvalidSignatureFormat
	}

	expectedSig := v.computeSignature(payload)

	// Use constant-time comparison to prevent timing attacks
	if !hmac.Equal(providedSigBytes, expectedSig) {
		return ErrInvalidSignature
	}

	return nil
}

// Sign generates a signature for the given payload.
// Returns the signature in the format "sha256=<hex-encoded-hmac>".
func (v *Verifier) Sign(payload []byte) string {
	sig := v.computeSignature(payload)
	return signaturePrefix + hex.EncodeToString(sig)
}

// computeSignature calculates the HMAC-SHA256 of the payload.
func (v *Verifier) computeSignature(payload []byte) []byte {
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(payload)
	return mac.Sum(nil)
}
