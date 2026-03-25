package vsphere

import "time"

// VMInfo contains vSphere VM identity information relevant for TPM EK binding.
type VMInfo struct {
	Name               string
	BIOSUUID           string
	MoRef              string
	HasVTPM            bool
	EKCertFingerprints []string // SHA-256 hex fingerprints of DER EK certs
	EKCertificatesDER  [][]byte // raw DER EK certs (for future activation mode)
	IPAddresses        []string
	LastSeen           time.Time
}
