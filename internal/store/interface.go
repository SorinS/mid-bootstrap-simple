package store

import (
	"time"

	"mid-bootstrap-server.git/internal/types"
)

// PaginationParams holds pagination parameters
type PaginationParams struct {
	Offset int // Number of items to skip
	Limit  int // Maximum number of items to return (0 = no limit)
}

// PaginatedRequests holds paginated machine request results
type PaginatedRequests struct {
	Data   []*types.MachineRequest `json:"data"`
	Total  int                     `json:"total"`
	Offset int                     `json:"offset"`
	Limit  int                     `json:"limit"`
}

// PaginatedRegistrations holds paginated agent registration results
type PaginatedRegistrations struct {
	Data   []*types.AgentRegistration `json:"data"`
	Total  int                        `json:"total"`
	Offset int                        `json:"offset"`
	Limit  int                        `json:"limit"`
}

// PaginatedAlerts holds paginated alert results
type PaginatedAlerts struct {
	Data   []*types.Alert `json:"data"`
	Total  int            `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
}

// DefaultPagination returns default pagination params (first 50 items)
func DefaultPagination() PaginationParams {
	return PaginationParams{Offset: 0, Limit: 50}
}

// Store defines the interface for bootstrap request storage
type Store interface {
	// AddOrUpdate adds a new request or updates an existing one
	// Returns the request (new or existing) and whether it was newly created
	AddOrUpdate(req *types.AutoBootstrapRequest, clientIP string) (*types.MachineRequest, bool)

	// Get retrieves a request by ID
	Get(id string) (*types.MachineRequest, error)

	// GetByHostname retrieves a request by hostname
	GetByHostname(hostname string) (*types.MachineRequest, error)

	// List returns all requests, sorted by creation time (newest first)
	List() []*types.MachineRequest

	// ListPaginated returns paginated requests, sorted by creation time (newest first)
	ListPaginated(params PaginationParams) *PaginatedRequests

	// ListByStatus returns requests with a specific status
	ListByStatus(status types.RequestStatus) []*types.MachineRequest

	// ListByStatusPaginated returns paginated requests with a specific status
	ListByStatusPaginated(status types.RequestStatus, params PaginationParams) *PaginatedRequests

	// CountRequests returns the total number of requests
	CountRequests() int

	// Approve marks a request as approved and stores the bootstrap token
	Approve(id string, approvedBy string, token *types.BootstrapToken) error

	// ClearToken removes the token from an approved request (after delivery)
	ClearToken(id string)

	// ResetToPending resets an approved request back to pending status
	ResetToPending(id string)

	// ClaimToken atomically claims a token for delivery (prevents race conditions)
	// Returns the token if available and status was approved, nil otherwise
	// After claiming, the token is cleared and status reset to pending
	ClaimToken(id string) *types.BootstrapToken

	// Deny marks a request as denied
	Deny(id string, deniedBy string, reason string) error

	// Delete removes a request
	Delete(id string) error

	// CleanupExpired removes requests older than the given TTL
	CleanupExpired(ttl time.Duration) int

	// Stats returns dashboard statistics
	Stats() *types.DashboardStats

	// GetQueuePosition returns the position of a request in the pending queue
	GetQueuePosition(id string) int

	// UpdateNonce updates the last nonce for a request (for TPM verification)
	UpdateNonce(id string, nonce []byte) error

	// UpdateTPMVerification updates TPM verification status and errors
	UpdateTPMVerification(id string, verified bool, errors []string) error

	// Close closes the store (for cleanup)
	Close() error

	// --- Agent Registration Methods ---

	// UpsertRegistration adds or updates an agent registration
	UpsertRegistration(reg *types.AgentRegistration) error

	// GetRegistration retrieves a registration by agent ID
	GetRegistration(agentID string) (*types.AgentRegistration, error)

	// ListRegistrations returns all registrations, sorted by last seen (newest first)
	ListRegistrations() []*types.AgentRegistration

	// ListRegistrationsPaginated returns paginated registrations, sorted by last seen (newest first)
	ListRegistrationsPaginated(params PaginationParams) *PaginatedRegistrations

	// CountRegistrations returns the total number of registrations
	CountRegistrations() int

	// DeleteRegistration removes a registration
	DeleteRegistration(agentID string) error

	// SystemStats returns statistics about registered agents
	SystemStats() *types.SystemStats

	// --- Audit Log Methods ---

	// AddAuditEntry adds an entry to the audit log
	AddAuditEntry(entry *types.AuditEntry) error

	// ListAuditLog returns audit entries, newest first, with optional limit
	ListAuditLog(limit int) []*types.AuditEntry

	// ListAuditLogByHostname returns audit entries for a specific hostname
	ListAuditLogByHostname(hostname string, limit int) []*types.AuditEntry

	// ListAuditLogByEventType returns audit entries of a specific type
	ListAuditLogByEventType(eventType types.AuditEventType, limit int) []*types.AuditEntry

	// --- Alert Methods ---

	// AddAlert adds a new alert
	AddAlert(alert *types.Alert) error

	// GetAlert retrieves an alert by ID
	GetAlert(id string) (*types.Alert, error)

	// ListAlerts returns all alerts, sorted by creation time (newest first)
	ListAlerts() []*types.Alert

	// ListUnacknowledgedAlerts returns alerts that haven't been acknowledged
	ListUnacknowledgedAlerts() []*types.Alert

	// ListAlertsByType returns alerts of a specific type
	ListAlertsByType(alertType types.AlertType) []*types.Alert

	// AcknowledgeAlert marks an alert as acknowledged
	AcknowledgeAlert(id string, acknowledgedBy string) error

	// ResolveAlert marks an alert as resolved (e.g., after deleting old version)
	ResolveAlert(id string, resolvedBy string, resolution string) error

	// DeleteAlert removes an alert
	DeleteAlert(id string) error

	// AlertStats returns statistics about alerts
	AlertStats() *types.AlertStats

	// GetAlertByAgentVersion returns an alert for a specific agent ID and version (for deduplication)
	GetAlertByAgentVersion(agentID string, version string) (*types.Alert, error)

	// --- Registration History for Version Change Detection ---

	// GetAllRegistrationsByHostname returns all registrations for a hostname (including old versions)
	GetAllRegistrationsByHostname(hostname string) []*types.AgentRegistration
}
