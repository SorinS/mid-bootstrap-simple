package types

import (
	"sync"
	"time"
)

// MachineRequest represents an auto-bootstrap request from an agent
type MachineRequest struct {
	ID        string    `json:"id"`         // Unique request ID
	CreatedAt time.Time `json:"created_at"` // When the request was received
	UpdatedAt time.Time `json:"updated_at"` // Last status update

	// Machine identification
	Hostname     string   `json:"hostname"`
	MachineID    string   `json:"machine_id,omitempty"`
	IPAddresses  []string `json:"ip_addresses"`
	MACAddresses []string `json:"mac_addresses,omitempty"`

	// System information
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	OSVersion     string `json:"os_version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	AgentVersion  string `json:"agent_version,omitempty"`

	// TPM attestation (if provided)
	HasTPM         bool             `json:"has_tpm"`
	TPMAttestation *TPMAttestation  `json:"tpm_attestation,omitempty"`

	// Request status
	Status       RequestStatus `json:"status"`
	StatusReason string        `json:"status_reason,omitempty"`

	// Approval tracking
	ApprovedBy   string     `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty"`
	DeniedBy     string     `json:"denied_by,omitempty"`
	DeniedAt     *time.Time `json:"denied_at,omitempty"`
	DenialReason string     `json:"denial_reason,omitempty"`

	// Token (populated after approval)
	Token *BootstrapToken `json:"token,omitempty"`

	// Client tracking
	ClientIP     string    `json:"client_ip"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	RequestCount int       `json:"request_count"` // Number of times this machine has called

	// TPM challenge nonce (for verifying attestation freshness)
	LastNonce []byte `json:"last_nonce,omitempty"`
}

// RequestStatus represents the status of a bootstrap request
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
	StatusError    RequestStatus = "error"
)

// TPMAttestation contains TPM attestation data from the agent
type TPMAttestation struct {
	Quote         []byte   `json:"quote"`
	Signature     []byte   `json:"signature"`
	PCRs          []byte   `json:"pcrs"`
	PCRDigest     []byte   `json:"pcr_digest"`
	AKPublic      []byte   `json:"ak_public"`
	AKPublicPEM   string   `json:"ak_public_pem,omitempty"` // PEM format (preferred for verification)
	AKCertificate []byte   `json:"ak_certificate,omitempty"`
	EKCertificate []byte   `json:"ek_certificate,omitempty"`
	EKPublic      []byte   `json:"ek_public,omitempty"`
	Nonce         []byte   `json:"nonce"`
	Verified      bool     `json:"verified"`
	VerifyErrors  []string `json:"verify_errors,omitempty"`
}

// BootstrapToken contains the token issued to an approved machine
type BootstrapToken struct {
	Token     string `json:"token"`
	TokenID   string `json:"token_id"`
	AgentID   string `json:"agent_id"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
	TTL       int    `json:"ttl"`
}

// AutoBootstrapRequest is the request body from the agent
type AutoBootstrapRequest struct {
	Hostname       string         `json:"hostname"`
	MachineID      string         `json:"machine_id,omitempty"`
	IPAddresses    []string       `json:"ip_addresses"`
	MACAddresses   []string       `json:"mac_addresses,omitempty"`
	OS             string         `json:"os"`
	Arch           string         `json:"arch"`
	OSVersion      string         `json:"os_version"`
	UptimeSeconds  int64          `json:"uptime_seconds"`
	AgentVersion   string         `json:"agent_version,omitempty"`
	TPMAttestation *TPMAttestation `json:"tpm_attestation,omitempty"`
}

// AutoBootstrapResponse is returned to the agent
type AutoBootstrapResponse struct {
	Status             string              `json:"status"`
	Message            string              `json:"message,omitempty"`
	Type               string              `json:"type,omitempty"` // "token" or "certificate" - kind of bootstrap credential
	Nonce              []byte              `json:"nonce,omitempty"`
	ProvisioningWindow *ProvisioningWindow `json:"provisioning_window,omitempty"`
	Token              *BootstrapToken     `json:"token,omitempty"`
	QueuePosition      int                 `json:"queue_position,omitempty"`
	RetryAfterSeconds  int                 `json:"retry_after_seconds,omitempty"`
}

// ProvisioningWindow defines when machines can be provisioned
type ProvisioningWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ApprovalRequest is sent by the operator to approve a machine
type ApprovalRequest struct {
	RequestID  string `json:"request_id"`
	ApprovedBy string `json:"approved_by"`
	Comment    string `json:"comment,omitempty"`
}

// DenialRequest is sent by the operator to deny a machine
type DenialRequest struct {
	RequestID string `json:"request_id"`
	DeniedBy  string `json:"denied_by"`
	Reason    string `json:"reason"`
}

// DashboardStats contains statistics for the web dashboard
type DashboardStats struct {
	TotalRequests    int `json:"total_requests"`
	PendingRequests  int `json:"pending_requests"`
	ApprovedRequests int `json:"approved_requests"`
	DeniedRequests   int `json:"denied_requests"`
	ExpiredRequests  int `json:"expired_requests"`
}

// RequestList is a thread-safe list of requests for the dashboard
type RequestList struct {
	mu       sync.RWMutex
	Requests []*MachineRequest `json:"requests"`
}

// Add adds a request to the list
func (rl *RequestList) Add(r *MachineRequest) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.Requests = append(rl.Requests, r)
}

// GetAll returns all requests
func (rl *RequestList) GetAll() []*MachineRequest {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	result := make([]*MachineRequest, len(rl.Requests))
	copy(result, rl.Requests)
	return result
}

// AgentRegistration represents a registration/heartbeat from an agent
type AgentRegistration struct {
	// Agent identification
	AgentID      string   `json:"agent_id"`
	Hostname     string   `json:"hostname"`
	IPAddresses  []string `json:"ip_addresses"`
	MACAddresses []string `json:"mac_addresses,omitempty"`

	// System information
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`

	// Runtime info
	UptimeSeconds int64  `json:"uptime_seconds"`
	BinaryPath    string `json:"binary_path,omitempty"`
	WorkingDir    string `json:"working_dir,omitempty"`

	// SPIFFE/CA status
	CAStatus *CAStatus `json:"ca_status,omitempty"`

	// Timestamp from agent
	Timestamp time.Time `json:"timestamp"`

	// Server-side metadata
	ClientIP      string    `json:"client_ip"`
	ReceivedAt    time.Time `json:"received_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	RegisterCount int       `json:"register_count"` // Number of registrations received

	// mTLS verification
	CertVerified bool   `json:"cert_verified"`          // Whether registration was verified with client cert
	CertIdentity string `json:"cert_identity,omitempty"` // Identity from client certificate (CN or SPIFFE ID)

	// PoW (Proof of Work) anti-spoofing - advisory mode
	SecureHeartbeat *SecureHeartbeat       `json:"secure_heartbeat,omitempty"` // Secure heartbeat from agent
	PoWVerification *PoWVerificationResult `json:"pow_verification,omitempty"` // Verification result (server-side)
	PoWStatus       string                 `json:"pow_status,omitempty"`       // "ok", "warning", "failed", "disabled"
}

// CAStatus represents the CA status from an agent
type CAStatus struct {
	Ready          bool       `json:"ready"`
	IssuedAt       *time.Time `json:"issued_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RenewalETA     *time.Time `json:"renewal_eta,omitempty"`
	CommonName     string     `json:"common_name,omitempty"`
	SerialNumber   string     `json:"serial_number,omitempty"`
	RemainingTTL   string     `json:"remaining_ttl,omitempty"`
	RenewalMethod  string     `json:"renewal_method,omitempty"`
	LastRenewalErr string     `json:"last_renewal_err,omitempty"`
}

// SystemStats contains statistics for the system dashboard
type SystemStats struct {
	TotalAgents   int `json:"total_agents"`
	ActiveAgents  int `json:"active_agents"`   // Seen in last 5 minutes
	CAReadyAgents int `json:"ca_ready_agents"` // Agents with CA ready
}

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	AuditEventApproval        AuditEventType = "approval"
	AuditEventDenial          AuditEventType = "denial"
	AuditEventTokenDelivered  AuditEventType = "token_delivered"
	AuditEventResetToPending  AuditEventType = "reset_to_pending"
	AuditEventAutoApproval    AuditEventType = "auto_approval"
	AuditEventManualBootstrap AuditEventType = "manual_bootstrap"
)

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID           int64          `json:"id"`
	Timestamp    time.Time      `json:"timestamp"`
	EventType    AuditEventType `json:"event_type"`
	RequestID    string         `json:"request_id,omitempty"`
	Hostname     string         `json:"hostname,omitempty"`
	MachineID    string         `json:"machine_id,omitempty"`
	IPAddresses  []string       `json:"ip_addresses,omitempty"`
	MACAddresses []string       `json:"mac_addresses,omitempty"`
	OS           string         `json:"os,omitempty"`
	Arch         string         `json:"arch,omitempty"`
	PerformedBy  string         `json:"performed_by,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	TokenID      string         `json:"token_id,omitempty"`
	ClientIP     string         `json:"client_ip,omitempty"`
	Details      string         `json:"details,omitempty"` // JSON string for extra info
}

// PoW (Proof of Work) types for anti-spoofing verification

// SecureHeartbeat represents a tamper-evident heartbeat with proof chain
type SecureHeartbeat struct {
	// Identity
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	Timestamp int64  `json:"timestamp"` // Unix timestamp

	// Proof chain - links to previous heartbeats
	Sequence     uint64 `json:"sequence"`      // Monotonic counter
	PreviousHash []byte `json:"previous_hash"` // Hash of previous heartbeat
	MerkleRoot   []byte `json:"merkle_root"`   // Root of all previous heartbeats

	// Proof of work
	Nonce      uint64 `json:"nonce"`      // PoW nonce
	Difficulty uint8  `json:"difficulty"` // Required leading zero bits
	WorkHash   []byte `json:"work_hash"`  // Hash meeting difficulty

	// Hardware binding
	SystemMetrics *PoWSystemMetrics `json:"system_metrics,omitempty"`
	TPMQuote      []byte            `json:"tpm_quote,omitempty"`

	// Subnet witnesses
	Witnesses []WitnessStatement `json:"witnesses,omitempty"`

	// Signature over all above fields
	Signature []byte `json:"signature"`

	// Public key for signature verification
	PublicKey []byte `json:"public_key,omitempty"`
}

// PoWSystemMetrics contains hardware-bound system information
type PoWSystemMetrics struct {
	BootID        string   `json:"boot_id"`
	BootTime      int64    `json:"boot_time"`
	UptimeSeconds int64    `json:"uptime_seconds"`
	MACAddresses  []string `json:"mac_addresses"`
	DiskSerial    string   `json:"disk_serial,omitempty"`
	MachineID     string   `json:"machine_id,omitempty"`
	Hostname      string   `json:"hostname"`
	KernelVersion string   `json:"kernel_version,omitempty"`
	DMISerial     string   `json:"dmi_serial,omitempty"`
	ProductUUID   string   `json:"product_uuid,omitempty"`
}

// WitnessStatement is a signed attestation from a neighboring agent
type WitnessStatement struct {
	WitnessID   string `json:"witness_id"`
	WitnessAddr string `json:"witness_addr"`
	SubjectID   string `json:"subject_id"`
	Timestamp   int64  `json:"timestamp"`
	Nonce       []byte `json:"nonce"`
	Signature   []byte `json:"signature"`
}

// PoWVerificationResult contains the result of verifying a secure heartbeat
type PoWVerificationResult struct {
	Valid            bool     `json:"valid"`
	ChainValid       bool     `json:"chain_valid"`
	WorkValid        bool     `json:"work_valid"`
	MetricsValid     bool     `json:"metrics_valid"`
	WitnessCount     int      `json:"witness_count"`
	WitnessThreshold int      `json:"witness_threshold"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypeStaleAgent    AlertType = "stale_agent"    // Agent hasn't sent heartbeat in configured time
	AlertTypeVersionChange AlertType = "version_change" // Agent version changed (old version entry)
)

// AlertSeverity represents the severity level of an alert
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// Alert represents an alert for operator attention
type Alert struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	Type      AlertType     `json:"type"`
	Severity  AlertSeverity `json:"severity"`

	// Agent information
	AgentID      string `json:"agent_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version,omitempty"`

	// Alert details
	Message string `json:"message"`
	Details string `json:"details,omitempty"` // JSON for extra info

	// For version change alerts
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`

	// For stale agent alerts
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	StaleDurationMin int        `json:"stale_duration_min,omitempty"`

	// Acknowledgement
	Acknowledged   bool       `json:"acknowledged"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`

	// Resolution
	Resolved   bool       `json:"resolved"`
	ResolvedBy string     `json:"resolved_by,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Resolution string     `json:"resolution,omitempty"` // e.g., "deleted_old_version", "agent_recovered"
}

// AlertStats contains statistics for the alerts dashboard
type AlertStats struct {
	TotalAlerts        int `json:"total_alerts"`
	UnacknowledgedCount int `json:"unacknowledged_count"`
	StaleAgentCount    int `json:"stale_agent_count"`
	VersionChangeCount int `json:"version_change_count"`
}

// AlertConfig contains configurable thresholds for alerts
type AlertConfig struct {
	StaleAgentMinutes int  `json:"stale_agent_minutes"` // Minutes before agent is considered stale (default: 10)
	EnableWebSocket   bool `json:"enable_websocket"`    // Enable WebSocket notifications for alerts
}
