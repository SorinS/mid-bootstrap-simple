package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"mid-bootstrap-server.git/internal/types"
)

// MemoryStore holds all bootstrap requests in memory
type MemoryStore struct {
	mu       sync.RWMutex
	requests map[string]*types.MachineRequest // keyed by request ID
	byHost   map[string]string                // hostname -> request ID (most recent)
	byMAC    map[string]string                // MAC address -> request ID

	// Agent registrations
	registrations map[string]*types.AgentRegistration // keyed by agent ID

	// Alerts
	alerts map[string]*types.Alert // keyed by alert ID
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		requests:      make(map[string]*types.MachineRequest),
		byHost:        make(map[string]string),
		byMAC:         make(map[string]string),
		registrations: make(map[string]*types.AgentRegistration),
		alerts:        make(map[string]*types.Alert),
	}
}

// Close implements Store interface (no-op for memory store)
func (s *MemoryStore) Close() error {
	return nil
}

// generateID creates a unique request ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// AddOrUpdate adds a new request or updates an existing one
// Returns the request (new or existing) and whether it was newly created
func (s *MemoryStore) AddOrUpdate(req *types.AutoBootstrapRequest, clientIP string) (*types.MachineRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Check if we have an existing request for this machine
	// First by MAC address, then by hostname
	var existingID string
	for _, mac := range req.MACAddresses {
		if id, ok := s.byMAC[mac]; ok {
			existingID = id
			break
		}
	}
	if existingID == "" {
		if id, ok := s.byHost[req.Hostname]; ok {
			existingID = id
		}
	}

	// If we have an existing request, update it
	if existingID != "" {
		existing := s.requests[existingID]
		if existing != nil {
			// Update last seen and request count
			existing.LastSeenAt = now
			existing.UpdatedAt = now
			existing.RequestCount++
			existing.ClientIP = clientIP

			// Update system info (might have changed)
			existing.UptimeSeconds = req.UptimeSeconds
			existing.OSVersion = req.OSVersion
			existing.AgentVersion = req.AgentVersion

			// Update TPM attestation if provided
			if req.TPMAttestation != nil {
				existing.HasTPM = true
				existing.TPMAttestation = req.TPMAttestation
			}

			return existing, false
		}
	}

	// Create new request
	newReq := &types.MachineRequest{
		ID:            generateID(),
		CreatedAt:     now,
		UpdatedAt:     now,
		Hostname:      req.Hostname,
		MachineID:     req.MachineID,
		IPAddresses:   req.IPAddresses,
		MACAddresses:  req.MACAddresses,
		OS:            req.OS,
		Arch:          req.Arch,
		OSVersion:     req.OSVersion,
		UptimeSeconds: req.UptimeSeconds,
		AgentVersion:  req.AgentVersion,
		Status:        types.StatusPending,
		ClientIP:      clientIP,
		LastSeenAt:    now,
		RequestCount:  1,
	}

	if req.TPMAttestation != nil {
		newReq.HasTPM = true
		newReq.TPMAttestation = req.TPMAttestation
	}

	// Store the request
	s.requests[newReq.ID] = newReq
	s.byHost[newReq.Hostname] = newReq.ID
	for _, mac := range newReq.MACAddresses {
		s.byMAC[mac] = newReq.ID
	}

	return newReq, true
}

// Get retrieves a request by ID
func (s *MemoryStore) Get(id string) (*types.MachineRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.requests[id]
	if !ok {
		return nil, fmt.Errorf("request not found: %s", id)
	}
	return req, nil
}

// GetByHostname retrieves a request by hostname
func (s *MemoryStore) GetByHostname(hostname string) (*types.MachineRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.byHost[hostname]
	if !ok {
		return nil, fmt.Errorf("no request found for hostname: %s", hostname)
	}
	return s.requests[id], nil
}

// List returns all requests, sorted by creation time (newest first)
func (s *MemoryStore) List() []*types.MachineRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*types.MachineRequest, 0, len(s.requests))
	for _, req := range s.requests {
		result = append(result, req)
	}

	// Sort by creation time, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result
}

// ListByStatus returns requests with a specific status
func (s *MemoryStore) ListByStatus(status types.RequestStatus) []*types.MachineRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*types.MachineRequest
	for _, req := range s.requests {
		if req.Status == status {
			result = append(result, req)
		}
	}

	// Sort by creation time, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result
}

// ListPaginated returns paginated requests, sorted by creation time (newest first)
func (s *MemoryStore) ListPaginated(params PaginationParams) *PaginatedRequests {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all and sort
	result := make([]*types.MachineRequest, 0, len(s.requests))
	for _, req := range s.requests {
		result = append(result, req)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	total := len(result)

	// Apply pagination
	if params.Offset >= len(result) {
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}

	result = result[params.Offset:]
	if params.Limit > 0 && len(result) > params.Limit {
		result = result[:params.Limit]
	}

	return &PaginatedRequests{
		Data:   result,
		Total:  total,
		Offset: params.Offset,
		Limit:  params.Limit,
	}
}

// ListByStatusPaginated returns paginated requests with a specific status
func (s *MemoryStore) ListByStatusPaginated(status types.RequestStatus, params PaginationParams) *PaginatedRequests {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*types.MachineRequest
	for _, req := range s.requests {
		if req.Status == status {
			result = append(result, req)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	total := len(result)

	// Apply pagination
	if params.Offset >= len(result) {
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}

	result = result[params.Offset:]
	if params.Limit > 0 && len(result) > params.Limit {
		result = result[:params.Limit]
	}

	return &PaginatedRequests{
		Data:   result,
		Total:  total,
		Offset: params.Offset,
		Limit:  params.Limit,
	}
}

// CountRequests returns the total number of requests
func (s *MemoryStore) CountRequests() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.requests)
}

// Approve marks a request as approved and stores the bootstrap token
func (s *MemoryStore) Approve(id string, approvedBy string, token *types.BootstrapToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("request not found: %s", id)
	}

	if req.Status != types.StatusPending {
		return fmt.Errorf("request is not pending: current status is %s", req.Status)
	}

	now := time.Now()
	req.Status = types.StatusApproved
	req.ApprovedBy = approvedBy
	req.ApprovedAt = &now
	req.UpdatedAt = now
	req.Token = token

	return nil
}

// ClearToken removes the token from an approved request (after delivery)
func (s *MemoryStore) ClearToken(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return
	}
	req.Token = nil
}

// ResetToPending resets an approved request back to pending status
// This requires operator re-approval for the next bootstrap
func (s *MemoryStore) ResetToPending(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return
	}

	req.Status = types.StatusPending
	req.Token = nil
	req.ApprovedBy = ""
	req.ApprovedAt = nil
	req.UpdatedAt = time.Now()
}

// ClaimToken atomically claims a token for delivery (prevents race conditions)
// Returns the token if available and status was approved, nil otherwise
// After claiming, the token is cleared and status reset to pending
func (s *MemoryStore) ClaimToken(id string) *types.BootstrapToken {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return nil
	}

	// Only claim if status is approved and token exists
	if req.Status != types.StatusApproved || req.Token == nil {
		return nil
	}

	// Atomically get the token and clear it
	token := req.Token
	req.Status = types.StatusPending
	req.Token = nil
	req.ApprovedBy = ""
	req.ApprovedAt = nil
	req.UpdatedAt = time.Now()

	return token
}

// Deny marks a request as denied
func (s *MemoryStore) Deny(id string, deniedBy string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("request not found: %s", id)
	}

	if req.Status != types.StatusPending {
		return fmt.Errorf("request is not pending: current status is %s", req.Status)
	}

	now := time.Now()
	req.Status = types.StatusDenied
	req.DeniedBy = deniedBy
	req.DeniedAt = &now
	req.DenialReason = reason
	req.UpdatedAt = now

	return nil
}

// Delete removes a request
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("request not found: %s", id)
	}

	// Clean up indexes
	delete(s.byHost, req.Hostname)
	for _, mac := range req.MACAddresses {
		delete(s.byMAC, mac)
	}
	delete(s.requests, id)

	return nil
}

// UpdateNonce updates the last nonce for a request (for TPM verification)
func (s *MemoryStore) UpdateNonce(id string, nonce []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("request not found: %s", id)
	}

	req.LastNonce = nonce
	return nil
}

// UpdateTPMVerification updates TPM verification status and errors
func (s *MemoryStore) UpdateTPMVerification(id string, verified bool, errors []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return fmt.Errorf("request not found: %s", id)
	}

	if req.TPMAttestation != nil {
		req.TPMAttestation.Verified = verified
		req.TPMAttestation.VerifyErrors = errors
	}
	return nil
}

// CleanupExpired removes requests older than the given TTL
func (s *MemoryStore) CleanupExpired(ttl time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-ttl)
	var toDelete []string

	for id, req := range s.requests {
		// Only expire pending requests
		if req.Status == types.StatusPending && req.CreatedAt.Before(cutoff) {
			req.Status = types.StatusExpired
			toDelete = append(toDelete, id)
		}
		// Also clean up old approved/denied requests (after 7 days)
		if (req.Status == types.StatusApproved || req.Status == types.StatusDenied) &&
			req.UpdatedAt.Before(time.Now().Add(-7*24*time.Hour)) {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		req := s.requests[id]
		delete(s.byHost, req.Hostname)
		for _, mac := range req.MACAddresses {
			delete(s.byMAC, mac)
		}
		delete(s.requests, id)
	}

	return len(toDelete)
}

// Stats returns dashboard statistics
func (s *MemoryStore) Stats() *types.DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.DashboardStats{}
	for _, req := range s.requests {
		stats.TotalRequests++
		switch req.Status {
		case types.StatusPending:
			stats.PendingRequests++
		case types.StatusApproved:
			stats.ApprovedRequests++
		case types.StatusDenied:
			stats.DeniedRequests++
		case types.StatusExpired:
			stats.ExpiredRequests++
		}
	}
	return stats
}

// GetQueuePosition returns the position of a request in the pending queue
func (s *MemoryStore) GetQueuePosition(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all pending requests sorted by creation time
	var pending []*types.MachineRequest
	for _, req := range s.requests {
		if req.Status == types.StatusPending {
			pending = append(pending, req)
		}
	}

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})

	for i, req := range pending {
		if req.ID == id {
			return i + 1 // 1-indexed position
		}
	}

	return 0
}

// --- Agent Registration Methods ---

// UpsertRegistration adds or updates an agent registration
func (s *MemoryStore) UpsertRegistration(reg *types.AgentRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if existing, ok := s.registrations[reg.AgentID]; ok {
		// Update existing registration
		existing.Hostname = reg.Hostname
		existing.IPAddresses = reg.IPAddresses
		existing.MACAddresses = reg.MACAddresses
		existing.OS = reg.OS
		existing.OSVersion = reg.OSVersion
		existing.Arch = reg.Arch
		existing.AgentVersion = reg.AgentVersion
		existing.UptimeSeconds = reg.UptimeSeconds
		existing.BinaryPath = reg.BinaryPath
		existing.WorkingDir = reg.WorkingDir
		existing.CAStatus = reg.CAStatus
		existing.Timestamp = reg.Timestamp
		existing.ClientIP = reg.ClientIP
		existing.LastSeenAt = now
		existing.RegisterCount++
		existing.CertVerified = reg.CertVerified
		existing.CertIdentity = reg.CertIdentity
		existing.PoWStatus = reg.PoWStatus
		existing.PoWVerification = reg.PoWVerification
		existing.SecureHeartbeat = reg.SecureHeartbeat
	} else {
		// Create new registration
		reg.ReceivedAt = now
		reg.LastSeenAt = now
		reg.RegisterCount = 1
		s.registrations[reg.AgentID] = reg
	}

	return nil
}

// GetRegistration retrieves a registration by agent ID
func (s *MemoryStore) GetRegistration(agentID string) (*types.AgentRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	reg, ok := s.registrations[agentID]
	if !ok {
		return nil, fmt.Errorf("registration not found: %s", agentID)
	}
	return reg, nil
}

// deduplicateByHostname returns registrations deduplicated by hostname, keeping most recently seen
func (s *MemoryStore) deduplicateByHostname() []*types.AgentRegistration {
	byHostname := make(map[string]*types.AgentRegistration)
	for _, reg := range s.registrations {
		hostname := reg.Hostname
		if hostname == "" {
			hostname = reg.AgentID
		}
		existing, ok := byHostname[hostname]
		if !ok || reg.LastSeenAt.After(existing.LastSeenAt) {
			byHostname[hostname] = reg
		}
	}

	result := make([]*types.AgentRegistration, 0, len(byHostname))
	for _, reg := range byHostname {
		result = append(result, reg)
	}

	// Sort by last seen, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeenAt.After(result[j].LastSeenAt)
	})

	return result
}

// ListRegistrations returns all registrations deduplicated by hostname, sorted by last seen (newest first)
func (s *MemoryStore) ListRegistrations() []*types.AgentRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.deduplicateByHostname()
}

// ListRegistrationsPaginated returns paginated registrations deduplicated by hostname, sorted by last seen (newest first)
func (s *MemoryStore) ListRegistrationsPaginated(params PaginationParams) *PaginatedRegistrations {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := s.deduplicateByHostname()
	total := len(result)

	// Apply pagination
	if params.Offset >= len(result) {
		return &PaginatedRegistrations{Data: []*types.AgentRegistration{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}

	result = result[params.Offset:]
	if params.Limit > 0 && len(result) > params.Limit {
		result = result[:params.Limit]
	}

	return &PaginatedRegistrations{
		Data:   result,
		Total:  total,
		Offset: params.Offset,
		Limit:  params.Limit,
	}
}

// CountRegistrations returns the total number of unique agents (deduplicated by hostname)
func (s *MemoryStore) CountRegistrations() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byHostname := make(map[string]struct{})
	for _, reg := range s.registrations {
		hostname := reg.Hostname
		if hostname == "" {
			hostname = reg.AgentID
		}
		byHostname[hostname] = struct{}{}
	}
	return len(byHostname)
}

// DeleteRegistration removes a registration
func (s *MemoryStore) DeleteRegistration(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.registrations[agentID]; !ok {
		return fmt.Errorf("registration not found: %s", agentID)
	}

	delete(s.registrations, agentID)
	return nil
}

// SystemStats returns statistics about registered agents
// Deduplicates agents by hostname (keeps most recently seen registration per hostname)
// This handles cases where agent ID changes (e.g., version upgrade changes ID)
func (s *MemoryStore) SystemStats() *types.SystemStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.SystemStats{}
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	// Deduplicate by hostname - keep only the most recently seen registration per hostname
	byHostname := make(map[string]*types.AgentRegistration)
	for _, reg := range s.registrations {
		hostname := reg.Hostname
		if hostname == "" {
			// Fallback to agent ID if hostname is empty
			hostname = reg.AgentID
		}
		existing, ok := byHostname[hostname]
		if !ok || reg.LastSeenAt.After(existing.LastSeenAt) {
			byHostname[hostname] = reg
		}
	}

	// Calculate stats from deduplicated registrations
	for _, reg := range byHostname {
		stats.TotalAgents++

		if reg.LastSeenAt.After(fiveMinutesAgo) {
			stats.ActiveAgents++
		}

		if reg.CAStatus != nil && reg.CAStatus.Ready {
			stats.CAReadyAgents++
		}
	}

	return stats
}

// --- Audit Log Methods (in-memory - not persisted) ---

// auditLog holds in-memory audit entries
var memoryAuditLog []*types.AuditEntry
var memoryAuditMu sync.RWMutex

// AddAuditEntry adds an entry to the audit log
func (s *MemoryStore) AddAuditEntry(entry *types.AuditEntry) error {
	memoryAuditMu.Lock()
	defer memoryAuditMu.Unlock()

	entry.ID = int64(len(memoryAuditLog) + 1)
	memoryAuditLog = append(memoryAuditLog, entry)
	return nil
}

// ListAuditLog returns audit entries, newest first, with optional limit
func (s *MemoryStore) ListAuditLog(limit int) []*types.AuditEntry {
	memoryAuditMu.RLock()
	defer memoryAuditMu.RUnlock()

	// Return in reverse order (newest first)
	result := make([]*types.AuditEntry, 0, len(memoryAuditLog))
	for i := len(memoryAuditLog) - 1; i >= 0; i-- {
		result = append(result, memoryAuditLog[i])
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

// ListAuditLogByHostname returns audit entries for a specific hostname
func (s *MemoryStore) ListAuditLogByHostname(hostname string, limit int) []*types.AuditEntry {
	memoryAuditMu.RLock()
	defer memoryAuditMu.RUnlock()

	var result []*types.AuditEntry
	for i := len(memoryAuditLog) - 1; i >= 0; i-- {
		if memoryAuditLog[i].Hostname == hostname {
			result = append(result, memoryAuditLog[i])
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result
}

// ListAuditLogByEventType returns audit entries of a specific type
func (s *MemoryStore) ListAuditLogByEventType(eventType types.AuditEventType, limit int) []*types.AuditEntry {
	memoryAuditMu.RLock()
	defer memoryAuditMu.RUnlock()

	var result []*types.AuditEntry
	for i := len(memoryAuditLog) - 1; i >= 0; i-- {
		if memoryAuditLog[i].EventType == eventType {
			result = append(result, memoryAuditLog[i])
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result
}

// --- Alert Methods ---

// AddAlert adds a new alert
func (s *MemoryStore) AddAlert(alert *types.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.ID == "" {
		alert.ID = generateID()
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = time.Now()
	}

	s.alerts[alert.ID] = alert
	return nil
}

// GetAlert retrieves an alert by ID
func (s *MemoryStore) GetAlert(id string) (*types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alert, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert not found: %s", id)
	}
	return alert, nil
}

// ListAlerts returns all alerts, sorted by creation time (newest first)
func (s *MemoryStore) ListAlerts() []*types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*types.Alert, 0, len(s.alerts))
	for _, alert := range s.alerts {
		result = append(result, alert)
	}

	// Sort by creation time, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result
}

// ListUnacknowledgedAlerts returns alerts that haven't been acknowledged
func (s *MemoryStore) ListUnacknowledgedAlerts() []*types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*types.Alert
	for _, alert := range s.alerts {
		if !alert.Acknowledged {
			result = append(result, alert)
		}
	}

	// Sort by creation time, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result
}

// ListAlertsByType returns alerts of a specific type
func (s *MemoryStore) ListAlertsByType(alertType types.AlertType) []*types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*types.Alert
	for _, alert := range s.alerts {
		if alert.Type == alertType {
			result = append(result, alert)
		}
	}

	// Sort by creation time, newest first
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	return result
}

// AcknowledgeAlert marks an alert as acknowledged
func (s *MemoryStore) AcknowledgeAlert(id string, acknowledgedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert not found: %s", id)
	}

	now := time.Now()
	alert.Acknowledged = true
	alert.AcknowledgedBy = acknowledgedBy
	alert.AcknowledgedAt = &now

	return nil
}

// ResolveAlert marks an alert as resolved
func (s *MemoryStore) ResolveAlert(id string, resolvedBy string, resolution string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alert, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert not found: %s", id)
	}

	now := time.Now()
	alert.Resolved = true
	alert.ResolvedBy = resolvedBy
	alert.ResolvedAt = &now
	alert.Resolution = resolution

	return nil
}

// DeleteAlert removes an alert
func (s *MemoryStore) DeleteAlert(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.alerts[id]; !ok {
		return fmt.Errorf("alert not found: %s", id)
	}

	delete(s.alerts, id)
	return nil
}

// AlertStats returns statistics about alerts
func (s *MemoryStore) AlertStats() *types.AlertStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.AlertStats{}

	for _, alert := range s.alerts {
		stats.TotalAlerts++

		if !alert.Acknowledged {
			stats.UnacknowledgedCount++
		}

		switch alert.Type {
		case types.AlertTypeStaleAgent:
			stats.StaleAgentCount++
		case types.AlertTypeVersionChange:
			stats.VersionChangeCount++
		}
	}

	return stats
}

// GetAlertByAgentVersion returns an alert for a specific agent ID and version
func (s *MemoryStore) GetAlertByAgentVersion(agentID string, version string) (*types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, alert := range s.alerts {
		if alert.AgentID == agentID && alert.AgentVersion == version {
			return alert, nil
		}
	}
	return nil, fmt.Errorf("alert not found for agent %s version %s", agentID, version)
}

// GetAllRegistrationsByHostname returns all registrations for a hostname (including old versions)
// Note: For memory store, we don't keep old versions, so this returns at most one registration
// This is used for version change detection - SQLite store can return multiple versions
func (s *MemoryStore) GetAllRegistrationsByHostname(hostname string) []*types.AgentRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*types.AgentRegistration
	for _, reg := range s.registrations {
		if reg.Hostname == hostname {
			result = append(result, reg)
		}
	}
	return result
}
