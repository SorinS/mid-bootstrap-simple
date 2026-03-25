package tpm

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// ComputeEKFingerprint returns the SHA-256 hex fingerprint of a DER-encoded EK certificate.
func ComputeEKFingerprint(derCert []byte) string {
	fp := sha256.Sum256(derCert)
	return fmt.Sprintf("%x", fp)
}

// MatchEKFingerprint checks if a DER-encoded EK certificate matches any of the expected fingerprints.
// Uses constant-time comparison to prevent timing attacks.
func MatchEKFingerprint(derCert []byte, expected []string) bool {
	actual := ComputeEKFingerprint(derCert)
	actualBytes, err := hex.DecodeString(actual)
	if err != nil {
		return false
	}

	for _, exp := range expected {
		expBytes, err := hex.DecodeString(exp)
		if err != nil {
			continue
		}
		if len(actualBytes) == len(expBytes) && subtle.ConstantTimeCompare(actualBytes, expBytes) == 1 {
			return true
		}
	}
	return false
}
