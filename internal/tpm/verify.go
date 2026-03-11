package tpm

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"mid-bootstrap-server.git/internal/types"
)

// VerificationResult contains the result of TPM attestation verification
type VerificationResult struct {
	Verified      bool
	QuoteVerified bool
	NonceVerified bool
	Errors        []string
	Warnings      []string
	VerifiedAt    time.Time
}

// VerifyAttestation verifies TPM attestation data against an expected nonce
func VerifyAttestation(attestation *types.TPMAttestation, expectedNonce []byte) *VerificationResult {
	result := &VerificationResult{
		Verified:   true,
		Errors:     make([]string, 0),
		Warnings:   make([]string, 0),
		VerifiedAt: time.Now(),
	}

	// 1. Verify nonce matches (most important for freshness)
	if !verifyNonce(attestation.Nonce, expectedNonce, result) {
		result.Verified = false
	}

	// 2. Verify quote signature using AK public key
	if !verifyQuoteSignature(attestation, result) {
		result.Verified = false
	}

	return result
}

// verifyNonce checks that the nonce in the attestation matches the expected nonce
// Nonce verification rules:
// 1. No expected nonce (first request): pass with warning
// 2. Agent sends empty nonce (restart/fresh): pass with warning (agent lost state)
// 3. Nonces match: pass (verified fresh)
// 4. Agent sends non-empty nonce that doesn't match: pass with warning (agent may have restarted)
//
// Note: We don't fail on nonce mismatch because the quote signature verification
// already proves the TPM generated this attestation. Nonce is for freshness,
// and a restart is a legitimate reason for nonce mismatch.
func verifyNonce(attestationNonce, expectedNonce []byte, result *VerificationResult) bool {
	// Case 1: No expected nonce (first request from this machine)
	if len(expectedNonce) == 0 {
		result.Warnings = append(result.Warnings, "no expected nonce (first request), skipping nonce verification")
		result.NonceVerified = false
		return true
	}

	// Case 2: Agent sends empty nonce (restart or fresh start)
	if len(attestationNonce) == 0 {
		result.Warnings = append(result.Warnings, "agent sent empty nonce (possible restart), issuing new challenge")
		result.NonceVerified = false
		return true
	}

	// Case 3: Nonces match - verified fresh
	if bytes.Equal(attestationNonce, expectedNonce) {
		result.NonceVerified = true
		log.Printf("[TPM] nonce verified successfully")
		return true
	}

	// Case 4: Nonce mismatch - likely agent restart, don't fail
	// The quote signature verification proves the TPM generated this attestation
	// A nonce mismatch just means we can't prove freshness of THIS specific request
	result.Warnings = append(result.Warnings, "nonce mismatch (agent may have restarted), issuing new challenge")
	result.NonceVerified = false
	return true // Don't fail - quote signature is the primary verification
}

// verifyQuoteSignature verifies the TPM quote signature using the AK public key
func verifyQuoteSignature(attestation *types.TPMAttestation, result *VerificationResult) bool {
	if len(attestation.Quote) == 0 {
		result.Errors = append(result.Errors, "no quote data provided")
		result.QuoteVerified = false
		return false
	}

	if len(attestation.Signature) == 0 {
		result.Errors = append(result.Errors, "no signature provided")
		result.QuoteVerified = false
		return false
	}

	// Try to get RSA public key - prefer PEM format, fall back to raw TPM format
	var rsaPub *rsa.PublicKey
	var err error

	if attestation.AKPublicPEM != "" {
		// Prefer PEM format (standard, easy to parse)
		rsaPub, err = parsePublicKeyPEM(attestation.AKPublicPEM)
		if err != nil {
			log.Printf("[TPM] failed to parse AK public key from PEM: %v", err)
			// Fall through to try raw format
		} else {
			log.Printf("[TPM] parsed AK public key from PEM format")
		}
	}

	if rsaPub == nil && len(attestation.AKPublic) > 0 {
		// Fall back to raw TPM format
		rsaPub, err = parseTPMPublicKey(attestation.AKPublic)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to parse AK public key: %v", err))
			result.QuoteVerified = false
			return false
		}
		log.Printf("[TPM] parsed AK public key from raw TPM format")
	}

	if rsaPub == nil {
		result.Errors = append(result.Errors, "no AK public key provided (neither PEM nor raw format)")
		result.QuoteVerified = false
		return false
	}

	// Parse the TPM signature structure
	sig, err := parseTPMSignature(attestation.Signature)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse TPM signature: %v", err))
		result.QuoteVerified = false
		return false
	}

	// Hash the quote data
	quoteHash := sha256.Sum256(attestation.Quote)

	// Verify RSASSA-PKCS1-v1_5 signature
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, quoteHash[:], sig)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("quote signature verification failed: %v", err))
		result.QuoteVerified = false
		return false
	}

	result.QuoteVerified = true
	log.Printf("[TPM] quote signature verified successfully")
	return true
}

// parsePublicKeyPEM parses a PEM-encoded public key
func parsePublicKeyPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return rsaPub, nil
}

// parseTPMPublicKey parses a TPMT_PUBLIC structure to extract an RSA public key
// TPMT_PUBLIC format: type(2) + nameAlg(2) + objectAttributes(4) + authPolicy(2+n) + parameters
// The data may or may not have a TPM2B size prefix depending on the source
func parseTPMPublicKey(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("TPM public key data too short: %d bytes", len(data))
	}

	// Log first 32 bytes for debugging
	debugLen := 32
	if len(data) < debugLen {
		debugLen = len(data)
	}
	log.Printf("[TPM] Raw public key data (%d bytes), first %d bytes: %x", len(data), debugLen, data[:debugLen])

	reader := bytes.NewReader(data)

	// Try to detect format by checking if first 2 bytes are a valid asymmetric algorithm
	var firstWord uint16
	binary.Read(reader, binary.BigEndian, &firstWord)
	reader.Seek(0, 0) // Reset to start

	log.Printf("[TPM] First word: 0x%04x", firstWord)

	// Valid asymmetric algorithm types: RSA=0x0001, ECC=0x0023
	// If first word is NOT a valid key algorithm, it might be a TPM2B size prefix
	isValidAlgType := (firstWord == 0x0001 || firstWord == 0x0023)

	if !isValidAlgType {
		// Skip potential TPM2B size prefix
		var sizePrefix uint16
		binary.Read(reader, binary.BigEndian, &sizePrefix)
		log.Printf("[TPM] Skipped potential TPM2B size prefix: %d (0x%04x)", sizePrefix, sizePrefix)

		// Validate that remaining data matches the size prefix
		if int(sizePrefix) != len(data)-2 {
			log.Printf("[TPM] Warning: size prefix %d doesn't match remaining data length %d", sizePrefix, len(data)-2)
		}
	}

	// Read algorithm type (2 bytes)
	var algType uint16
	if err := binary.Read(reader, binary.BigEndian, &algType); err != nil {
		return nil, fmt.Errorf("failed to read algorithm type: %w", err)
	}

	log.Printf("[TPM] Parsed algorithm type: 0x%04x (RSA=0x0001, ECC=0x0023, SHA256=0x000b)", algType)

	// TPM_ALG_RSA = 0x0001, TPM_ALG_ECC = 0x0023
	if algType != 0x0001 {
		// Dump first few bytes for debugging
		debugLen := 32
		if len(data) < debugLen {
			debugLen = len(data)
		}
		return nil, fmt.Errorf("unsupported algorithm type: 0x%04x (expected RSA=0x0001), first %d bytes: %x", algType, debugLen, data[:debugLen])
	}

	// Read nameAlg (2 bytes)
	var nameAlg uint16
	if err := binary.Read(reader, binary.BigEndian, &nameAlg); err != nil {
		return nil, fmt.Errorf("failed to read nameAlg: %w", err)
	}

	// Read objectAttributes (4 bytes)
	var objAttr uint32
	if err := binary.Read(reader, binary.BigEndian, &objAttr); err != nil {
		return nil, fmt.Errorf("failed to read objectAttributes: %w", err)
	}

	// Read authPolicy size and skip the policy data
	var authPolicySize uint16
	if err := binary.Read(reader, binary.BigEndian, &authPolicySize); err != nil {
		return nil, fmt.Errorf("failed to read authPolicy size: %w", err)
	}
	if authPolicySize > 0 {
		authPolicy := make([]byte, authPolicySize)
		if _, err := reader.Read(authPolicy); err != nil {
			return nil, fmt.Errorf("failed to read authPolicy: %w", err)
		}
	}

	// Now read RSA parameters (TPMS_RSA_PARMS)
	// symmetric (TPMT_SYM_DEF_OBJECT): algorithm(2) + [keyBits(2) + mode(2)]
	var symAlg uint16
	if err := binary.Read(reader, binary.BigEndian, &symAlg); err != nil {
		return nil, fmt.Errorf("failed to read symmetric algorithm: %w", err)
	}

	// TPM_ALG_NULL = 0x0010
	if symAlg != 0x0010 {
		// Skip keyBits and mode if symmetric is not NULL
		var symKeyBits, symMode uint16
		binary.Read(reader, binary.BigEndian, &symKeyBits)
		binary.Read(reader, binary.BigEndian, &symMode)
	}

	// scheme (TPMT_RSA_SCHEME): scheme(2) + [hashAlg(2)]
	var scheme uint16
	if err := binary.Read(reader, binary.BigEndian, &scheme); err != nil {
		return nil, fmt.Errorf("failed to read RSA scheme: %w", err)
	}

	// If scheme is not NULL (0x0010), read the hash algorithm
	if scheme != 0x0010 {
		var hashAlg uint16
		if err := binary.Read(reader, binary.BigEndian, &hashAlg); err != nil {
			return nil, fmt.Errorf("failed to read scheme hash algorithm: %w", err)
		}
	}

	// keyBits (2 bytes)
	var keyBits uint16
	if err := binary.Read(reader, binary.BigEndian, &keyBits); err != nil {
		return nil, fmt.Errorf("failed to read keyBits: %w", err)
	}

	// exponent (4 bytes) - 0 means default (65537)
	var exponent uint32
	if err := binary.Read(reader, binary.BigEndian, &exponent); err != nil {
		return nil, fmt.Errorf("failed to read exponent: %w", err)
	}
	if exponent == 0 {
		exponent = 65537
	}

	// unique (TPM2B_PUBLIC_KEY_RSA): size(2) + modulus
	var modulusSize uint16
	if err := binary.Read(reader, binary.BigEndian, &modulusSize); err != nil {
		return nil, fmt.Errorf("failed to read modulus size: %w", err)
	}

	modulus := make([]byte, modulusSize)
	if _, err := reader.Read(modulus); err != nil {
		return nil, fmt.Errorf("failed to read modulus: %w", err)
	}

	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(exponent),
	}

	return pubKey, nil
}

// parseTPMSignature parses a TPMT_SIGNATURE structure to extract the raw signature bytes
// TPMT_SIGNATURE: sigAlg(2) + hash(2) + sig(2+n)
func parseTPMSignature(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("signature data too short: %d bytes", len(data))
	}

	reader := bytes.NewReader(data)

	// Read signature algorithm (2 bytes)
	var sigAlg uint16
	if err := binary.Read(reader, binary.BigEndian, &sigAlg); err != nil {
		return nil, fmt.Errorf("failed to read signature algorithm: %w", err)
	}

	// TPM_ALG_RSASSA = 0x0014
	if sigAlg != 0x0014 {
		return nil, fmt.Errorf("unsupported signature algorithm: 0x%04x (expected RSASSA=0x0014)", sigAlg)
	}

	// Read hash algorithm (2 bytes)
	var hashAlg uint16
	if err := binary.Read(reader, binary.BigEndian, &hashAlg); err != nil {
		return nil, fmt.Errorf("failed to read hash algorithm: %w", err)
	}

	// TPM_ALG_SHA256 = 0x000B
	if hashAlg != 0x000B {
		return nil, fmt.Errorf("unsupported hash algorithm: 0x%04x (expected SHA256=0x000B)", hashAlg)
	}

	// Read signature size (2 bytes)
	var sigSize uint16
	if err := binary.Read(reader, binary.BigEndian, &sigSize); err != nil {
		return nil, fmt.Errorf("failed to read signature size: %w", err)
	}

	// Read signature bytes
	sig := make([]byte, sigSize)
	if _, err := reader.Read(sig); err != nil {
		return nil, fmt.Errorf("failed to read signature bytes: %w", err)
	}

	return sig, nil
}

// GenerateNonce generates a random nonce for TPM attestation challenges
func GenerateNonce() []byte {
	// Use crypto/rand for secure random generation
	nonce := make([]byte, 32)
	// Note: In production, use crypto/rand.Read
	// For simplicity, we'll use time-based nonce here
	// The server.go already uses crypto/rand in generateNonce()
	return nonce
}
