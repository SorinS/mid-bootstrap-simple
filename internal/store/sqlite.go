package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver (no CGO required)
	"mid-bootstrap-server.git/internal/types"
)

// SQLiteStore implements Store interface using SQLite
type SQLiteStore struct {
	db *sql.DB
	mu sync.RWMutex // For in-memory caches
}

// NewSQLiteStore creates a new SQLite-backed store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Using modernc.org/sqlite - pure Go, no CGO required
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	store := &SQLiteStore{db: db}

	// Create tables
	if err := store.createTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return store, nil
}

// createTables creates the required database tables
func (s *SQLiteStore) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS machine_requests (
		id TEXT PRIMARY KEY,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		hostname TEXT NOT NULL,
		machine_id TEXT,
		ip_addresses TEXT, -- JSON array
		mac_addresses TEXT, -- JSON array
		os TEXT,
		arch TEXT,
		os_version TEXT,
		uptime_seconds INTEGER,
		agent_version TEXT,
		has_tpm BOOLEAN DEFAULT FALSE,
		tpm_attestation TEXT, -- JSON object
		last_nonce BLOB, -- TPM challenge nonce
		status TEXT NOT NULL,
		status_reason TEXT,
		approved_by TEXT,
		approved_at DATETIME,
		denied_by TEXT,
		denied_at DATETIME,
		denial_reason TEXT,
		token TEXT, -- JSON object
		client_ip TEXT,
		last_seen_at DATETIME,
		request_count INTEGER DEFAULT 1
	);

	CREATE INDEX IF NOT EXISTS idx_hostname ON machine_requests(hostname);
	CREATE INDEX IF NOT EXISTS idx_status ON machine_requests(status);
	CREATE INDEX IF NOT EXISTS idx_created_at ON machine_requests(created_at);

	CREATE TABLE IF NOT EXISTS mac_index (
		mac_address TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		FOREIGN KEY (request_id) REFERENCES machine_requests(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS agent_registrations (
		agent_id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		ip_addresses TEXT, -- JSON array
		mac_addresses TEXT, -- JSON array
		os TEXT,
		os_version TEXT,
		arch TEXT,
		agent_version TEXT,
		uptime_seconds INTEGER,
		binary_path TEXT,
		working_dir TEXT,
		ca_status TEXT, -- JSON object
		mqtt_connected BOOLEAN DEFAULT FALSE,
		timestamp DATETIME,
		client_ip TEXT,
		received_at DATETIME NOT NULL,
		last_seen_at DATETIME NOT NULL,
		register_count INTEGER DEFAULT 1,
		cert_verified BOOLEAN DEFAULT FALSE,
		cert_identity TEXT,
		pow_status TEXT DEFAULT 'disabled',
		pow_verification TEXT, -- JSON object
		secure_heartbeat TEXT -- JSON object
	);

	CREATE INDEX IF NOT EXISTS idx_reg_hostname ON agent_registrations(hostname);
	CREATE INDEX IF NOT EXISTS idx_reg_last_seen ON agent_registrations(last_seen_at);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		event_type TEXT NOT NULL,  -- 'approval', 'denial', 'token_delivered', 'reset_to_pending'
		request_id TEXT,
		hostname TEXT,
		machine_id TEXT,
		ip_addresses TEXT,         -- JSON array
		mac_addresses TEXT,        -- JSON array
		os TEXT,
		arch TEXT,
		performed_by TEXT,         -- Who performed the action
		reason TEXT,               -- Denial reason or approval comment
		token_id TEXT,             -- Token ID if issued
		client_ip TEXT,            -- Client IP at time of action
		details TEXT               -- JSON object for additional details
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
	CREATE INDEX IF NOT EXISTS idx_audit_hostname ON audit_log(hostname);
	CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_log(request_id);

	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		created_at DATETIME NOT NULL,
		type TEXT NOT NULL,        -- 'stale_agent', 'version_change'
		severity TEXT NOT NULL,    -- 'info', 'warning', 'critical'
		agent_id TEXT NOT NULL,
		hostname TEXT NOT NULL,
		agent_version TEXT,
		message TEXT NOT NULL,
		details TEXT,              -- JSON for extra info
		old_version TEXT,          -- For version_change alerts
		new_version TEXT,          -- For version_change alerts
		last_seen_at DATETIME,     -- For stale_agent alerts
		stale_duration_min INTEGER,
		acknowledged BOOLEAN DEFAULT FALSE,
		acknowledged_by TEXT,
		acknowledged_at DATETIME,
		resolved BOOLEAN DEFAULT FALSE,
		resolved_by TEXT,
		resolved_at DATETIME,
		resolution TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
	CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);
	CREATE INDEX IF NOT EXISTS idx_alerts_hostname ON alerts(hostname);
	CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
	CREATE INDEX IF NOT EXISTS idx_alerts_agent_version ON alerts(agent_id, agent_version);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Run migrations for existing databases
	return s.runMigrations()
}

// runMigrations applies schema migrations for existing databases
func (s *SQLiteStore) runMigrations() error {
	// Add PoW columns to agent_registrations if they don't exist
	migrations := []string{
		`ALTER TABLE agent_registrations ADD COLUMN pow_status TEXT DEFAULT 'disabled'`,
		`ALTER TABLE agent_registrations ADD COLUMN pow_verification TEXT`,
		`ALTER TABLE agent_registrations ADD COLUMN secure_heartbeat TEXT`,
	}

	for _, migration := range migrations {
		// SQLite will error if column already exists, which is fine
		s.db.Exec(migration)
	}

	return nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// AddOrUpdate adds a new request or updates an existing one
func (s *SQLiteStore) AddOrUpdate(req *types.AutoBootstrapRequest, clientIP string) (*types.MachineRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Check for existing request by MAC or hostname
	var existingID string

	// Check by MAC address
	for _, mac := range req.MACAddresses {
		var id string
		err := s.db.QueryRow("SELECT request_id FROM mac_index WHERE mac_address = ?", mac).Scan(&id)
		if err == nil {
			existingID = id
			break
		}
	}

	// Check by hostname if not found by MAC
	if existingID == "" {
		var id string
		err := s.db.QueryRow("SELECT id FROM machine_requests WHERE hostname = ? ORDER BY created_at DESC LIMIT 1", req.Hostname).Scan(&id)
		if err == nil {
			existingID = id
		}
	}

	// If existing, update it
	if existingID != "" {
		existing, err := s.getByID(existingID)
		if err == nil && existing != nil {
			existing.LastSeenAt = now
			existing.UpdatedAt = now
			existing.RequestCount++
			existing.ClientIP = clientIP
			existing.UptimeSeconds = req.UptimeSeconds
			existing.OSVersion = req.OSVersion
			existing.AgentVersion = req.AgentVersion

			if req.TPMAttestation != nil {
				existing.HasTPM = true
				existing.TPMAttestation = convertTPMAttestation(req.TPMAttestation)
			}

			if err := s.updateRequest(existing); err != nil {
				// Log error but continue
				fmt.Printf("Error updating request: %v\n", err)
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
		newReq.TPMAttestation = convertTPMAttestation(req.TPMAttestation)
	}

	if err := s.insertRequest(newReq); err != nil {
		fmt.Printf("Error inserting request: %v\n", err)
		return nil, false
	}

	return newReq, true
}

// convertTPMAttestation converts from AutoBootstrapRequest TPM format to MachineRequest format
func convertTPMAttestation(src *types.TPMAttestation) *types.TPMAttestation {
	if src == nil {
		return nil
	}
	return src // Same type, just copy
}

// insertRequest inserts a new request into the database
func (s *SQLiteStore) insertRequest(req *types.MachineRequest) error {
	ipJSON, _ := json.Marshal(req.IPAddresses)
	macJSON, _ := json.Marshal(req.MACAddresses)
	tpmJSON, _ := json.Marshal(req.TPMAttestation)
	tokenJSON, _ := json.Marshal(req.Token)

	_, err := s.db.Exec(`
		INSERT INTO machine_requests (
			id, created_at, updated_at, hostname, machine_id, ip_addresses, mac_addresses,
			os, arch, os_version, uptime_seconds, agent_version, has_tpm, tpm_attestation,
			status, status_reason, approved_by, approved_at, denied_by, denied_at,
			denial_reason, token, client_ip, last_seen_at, request_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.CreatedAt, req.UpdatedAt, req.Hostname, req.MachineID,
		string(ipJSON), string(macJSON), req.OS, req.Arch, req.OSVersion,
		req.UptimeSeconds, req.AgentVersion, req.HasTPM, string(tpmJSON),
		string(req.Status), req.StatusReason, req.ApprovedBy, req.ApprovedAt,
		req.DeniedBy, req.DeniedAt, req.DenialReason, string(tokenJSON),
		req.ClientIP, req.LastSeenAt, req.RequestCount,
	)

	if err != nil {
		return err
	}

	// Index MAC addresses
	for _, mac := range req.MACAddresses {
		s.db.Exec("INSERT OR REPLACE INTO mac_index (mac_address, request_id) VALUES (?, ?)", mac, req.ID)
	}

	return nil
}

// updateRequest updates an existing request in the database
func (s *SQLiteStore) updateRequest(req *types.MachineRequest) error {
	ipJSON, _ := json.Marshal(req.IPAddresses)
	macJSON, _ := json.Marshal(req.MACAddresses)
	tpmJSON, _ := json.Marshal(req.TPMAttestation)
	tokenJSON, _ := json.Marshal(req.Token)

	_, err := s.db.Exec(`
		UPDATE machine_requests SET
			updated_at = ?, hostname = ?, machine_id = ?, ip_addresses = ?, mac_addresses = ?,
			os = ?, arch = ?, os_version = ?, uptime_seconds = ?, agent_version = ?,
			has_tpm = ?, tpm_attestation = ?, status = ?, status_reason = ?,
			approved_by = ?, approved_at = ?, denied_by = ?, denied_at = ?,
			denial_reason = ?, token = ?, client_ip = ?, last_seen_at = ?, request_count = ?
		WHERE id = ?`,
		req.UpdatedAt, req.Hostname, req.MachineID, string(ipJSON), string(macJSON),
		req.OS, req.Arch, req.OSVersion, req.UptimeSeconds, req.AgentVersion,
		req.HasTPM, string(tpmJSON), string(req.Status), req.StatusReason,
		req.ApprovedBy, req.ApprovedAt, req.DeniedBy, req.DeniedAt,
		req.DenialReason, string(tokenJSON), req.ClientIP, req.LastSeenAt,
		req.RequestCount, req.ID,
	)

	return err
}

// machineRequestColumns is the explicit column list for SELECT queries
// This ensures consistent column order regardless of schema migrations
const machineRequestColumns = `id, created_at, updated_at, hostname, machine_id,
	ip_addresses, mac_addresses, os, arch, os_version,
	uptime_seconds, agent_version, has_tpm, tpm_attestation, last_nonce,
	status, status_reason, approved_by, approved_at,
	denied_by, denied_at, denial_reason, token,
	client_ip, last_seen_at, request_count`

// getByID retrieves a request by ID (internal, no locking)
func (s *SQLiteStore) getByID(id string) (*types.MachineRequest, error) {
	row := s.db.QueryRow(`SELECT `+machineRequestColumns+` FROM machine_requests WHERE id = ?`, id)
	return s.scanRequest(row)
}

// scanRequest scans a row into a MachineRequest
func (s *SQLiteStore) scanRequest(row *sql.Row) (*types.MachineRequest, error) {
	var req types.MachineRequest
	// Use sql.NullString for nullable text columns
	var machineID, ipJSON, macJSON, os, arch, osVersion sql.NullString
	var agentVersion, tpmJSON, status, statusReason sql.NullString
	var approvedBy, deniedBy, denialReason, tokenJSON, clientIP sql.NullString
	var approvedAt, deniedAt, lastSeenAt sql.NullTime
	var uptimeSeconds sql.NullInt64
	var requestCount sql.NullInt64
	var lastNonce []byte

	err := row.Scan(
		&req.ID, &req.CreatedAt, &req.UpdatedAt, &req.Hostname, &machineID,
		&ipJSON, &macJSON, &os, &arch, &osVersion,
		&uptimeSeconds, &agentVersion, &req.HasTPM, &tpmJSON, &lastNonce,
		&status, &statusReason, &approvedBy, &approvedAt,
		&deniedBy, &deniedAt, &denialReason, &tokenJSON,
		&clientIP, &lastSeenAt, &requestCount,
	)
	if err != nil {
		return nil, err
	}

	// Map nullable values to struct fields
	req.MachineID = machineID.String
	req.OS = os.String
	req.Arch = arch.String
	req.OSVersion = osVersion.String
	req.AgentVersion = agentVersion.String
	req.StatusReason = statusReason.String
	req.ApprovedBy = approvedBy.String
	req.DeniedBy = deniedBy.String
	req.DenialReason = denialReason.String
	req.ClientIP = clientIP.String
	req.LastNonce = lastNonce
	if uptimeSeconds.Valid {
		req.UptimeSeconds = uptimeSeconds.Int64
	}
	if requestCount.Valid {
		req.RequestCount = int(requestCount.Int64)
	}
	if lastSeenAt.Valid {
		req.LastSeenAt = lastSeenAt.Time
	}
	if status.Valid {
		req.Status = types.RequestStatus(status.String)
	}
	if approvedAt.Valid {
		req.ApprovedAt = &approvedAt.Time
	}
	if deniedAt.Valid {
		req.DeniedAt = &deniedAt.Time
	}

	// Parse JSON fields
	if ipJSON.Valid {
		json.Unmarshal([]byte(ipJSON.String), &req.IPAddresses)
	}
	if macJSON.Valid {
		json.Unmarshal([]byte(macJSON.String), &req.MACAddresses)
	}
	if tpmJSON.Valid {
		json.Unmarshal([]byte(tpmJSON.String), &req.TPMAttestation)
	}
	if tokenJSON.Valid {
		json.Unmarshal([]byte(tokenJSON.String), &req.Token)
	}

	return &req, nil
}

// scanRequests scans multiple rows
func (s *SQLiteStore) scanRequests(rows *sql.Rows) ([]*types.MachineRequest, error) {
	var results []*types.MachineRequest

	for rows.Next() {
		var req types.MachineRequest
		// Use sql.NullString for nullable text columns
		var machineID, ipJSON, macJSON, os, arch, osVersion sql.NullString
		var agentVersion, tpmJSON, status, statusReason sql.NullString
		var approvedBy, deniedBy, denialReason, tokenJSON, clientIP sql.NullString
		var approvedAt, deniedAt, lastSeenAt sql.NullTime
		var uptimeSeconds sql.NullInt64
		var requestCount sql.NullInt64
		var lastNonce []byte

		err := rows.Scan(
			&req.ID, &req.CreatedAt, &req.UpdatedAt, &req.Hostname, &machineID,
			&ipJSON, &macJSON, &os, &arch, &osVersion,
			&uptimeSeconds, &agentVersion, &req.HasTPM, &tpmJSON, &lastNonce,
			&status, &statusReason, &approvedBy, &approvedAt,
			&deniedBy, &deniedAt, &denialReason, &tokenJSON,
			&clientIP, &lastSeenAt, &requestCount,
		)
		if err != nil {
			return nil, err
		}

		// Map nullable values to struct fields
		req.MachineID = machineID.String
		req.OS = os.String
		req.Arch = arch.String
		req.OSVersion = osVersion.String
		req.AgentVersion = agentVersion.String
		req.StatusReason = statusReason.String
		req.ApprovedBy = approvedBy.String
		req.DeniedBy = deniedBy.String
		req.DenialReason = denialReason.String
		req.ClientIP = clientIP.String
		req.LastNonce = lastNonce
		if uptimeSeconds.Valid {
			req.UptimeSeconds = uptimeSeconds.Int64
		}
		if requestCount.Valid {
			req.RequestCount = int(requestCount.Int64)
		}
		if lastSeenAt.Valid {
			req.LastSeenAt = lastSeenAt.Time
		}
		if status.Valid {
			req.Status = types.RequestStatus(status.String)
		}
		if approvedAt.Valid {
			req.ApprovedAt = &approvedAt.Time
		}
		if deniedAt.Valid {
			req.DeniedAt = &deniedAt.Time
		}

		// Parse JSON fields
		if ipJSON.Valid {
			json.Unmarshal([]byte(ipJSON.String), &req.IPAddresses)
		}
		if macJSON.Valid {
			json.Unmarshal([]byte(macJSON.String), &req.MACAddresses)
		}
		if tpmJSON.Valid {
			json.Unmarshal([]byte(tpmJSON.String), &req.TPMAttestation)
		}
		if tokenJSON.Valid {
			json.Unmarshal([]byte(tokenJSON.String), &req.Token)
		}

		results = append(results, &req)
	}

	return results, nil
}

// Get retrieves a request by ID
func (s *SQLiteStore) Get(id string) (*types.MachineRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, err := s.getByID(id)
	if err != nil {
		return nil, fmt.Errorf("request not found: %s", id)
	}
	return req, nil
}

// GetByHostname retrieves a request by hostname
func (s *SQLiteStore) GetByHostname(hostname string) (*types.MachineRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`SELECT `+machineRequestColumns+` FROM machine_requests WHERE hostname = ? ORDER BY created_at DESC LIMIT 1`, hostname)
	req, err := s.scanRequest(row)
	if err != nil {
		return nil, fmt.Errorf("no request found for hostname: %s", hostname)
	}
	return req, nil
}

// List returns all requests, sorted by creation time (newest first)
func (s *SQLiteStore) List() []*types.MachineRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT ` + machineRequestColumns + ` FROM machine_requests ORDER BY created_at DESC`)
	if err != nil {
		fmt.Printf("[SQLite] List query error: %v\n", err)
		return nil
	}
	defer rows.Close()

	results, err := s.scanRequests(rows)
	if err != nil {
		fmt.Printf("[SQLite] List scan error: %v\n", err)
		return nil
	}
	return results
}

// ListByStatus returns requests with a specific status
func (s *SQLiteStore) ListByStatus(status types.RequestStatus) []*types.MachineRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT `+machineRequestColumns+` FROM machine_requests WHERE status = ? ORDER BY created_at DESC`, string(status))
	if err != nil {
		fmt.Printf("[SQLite] ListByStatus query error: %v\n", err)
		return nil
	}
	defer rows.Close()

	results, err := s.scanRequests(rows)
	if err != nil {
		fmt.Printf("[SQLite] ListByStatus scan error: %v\n", err)
		return nil
	}
	return results
}

// ListPaginated returns paginated requests, sorted by creation time (newest first)
func (s *SQLiteStore) ListPaginated(params PaginationParams) *PaginatedRequests {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get total count
	var total int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests`).Scan(&total)
	if err != nil {
		fmt.Printf("[SQLite] ListPaginated count error: %v\n", err)
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: 0, Offset: params.Offset, Limit: params.Limit}
	}

	// Build query with pagination
	query := `SELECT ` + machineRequestColumns + ` FROM machine_requests ORDER BY created_at DESC`
	var rows *sql.Rows
	if params.Limit > 0 {
		query += ` LIMIT ? OFFSET ?`
		rows, err = s.db.Query(query, params.Limit, params.Offset)
	} else {
		rows, err = s.db.Query(query)
	}
	if err != nil {
		fmt.Printf("[SQLite] ListPaginated query error: %v\n", err)
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}
	defer rows.Close()

	results, err := s.scanRequests(rows)
	if err != nil {
		fmt.Printf("[SQLite] ListPaginated scan error: %v\n", err)
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}

	return &PaginatedRequests{
		Data:   results,
		Total:  total,
		Offset: params.Offset,
		Limit:  params.Limit,
	}
}

// ListByStatusPaginated returns paginated requests with a specific status
func (s *SQLiteStore) ListByStatusPaginated(status types.RequestStatus, params PaginationParams) *PaginatedRequests {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get total count for this status
	var total int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests WHERE status = ?`, string(status)).Scan(&total)
	if err != nil {
		fmt.Printf("[SQLite] ListByStatusPaginated count error: %v\n", err)
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: 0, Offset: params.Offset, Limit: params.Limit}
	}

	// Build query with pagination
	query := `SELECT ` + machineRequestColumns + ` FROM machine_requests WHERE status = ? ORDER BY created_at DESC`
	var rows *sql.Rows
	if params.Limit > 0 {
		query += ` LIMIT ? OFFSET ?`
		rows, err = s.db.Query(query, string(status), params.Limit, params.Offset)
	} else {
		rows, err = s.db.Query(query, string(status))
	}
	if err != nil {
		fmt.Printf("[SQLite] ListByStatusPaginated query error: %v\n", err)
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}
	defer rows.Close()

	results, err := s.scanRequests(rows)
	if err != nil {
		fmt.Printf("[SQLite] ListByStatusPaginated scan error: %v\n", err)
		return &PaginatedRequests{Data: []*types.MachineRequest{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}

	return &PaginatedRequests{
		Data:   results,
		Total:  total,
		Offset: params.Offset,
		Limit:  params.Limit,
	}
}

// CountRequests returns the total number of requests
func (s *SQLiteStore) CountRequests() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests`).Scan(&count)
	if err != nil {
		fmt.Printf("[SQLite] CountRequests error: %v\n", err)
		return 0
	}
	return count
}

// Approve marks a request as approved and stores the bootstrap token
func (s *SQLiteStore) Approve(id string, approvedBy string, token *types.BootstrapToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the request for audit log
	row := s.db.QueryRow(`SELECT hostname, machine_id, ip_addresses, mac_addresses, os, arch, client_ip, status
		FROM machine_requests WHERE id = ?`, id)
	var hostname, machineID, ipJSON, macJSON, osName, arch, clientIP, currentStatus sql.NullString
	err := row.Scan(&hostname, &machineID, &ipJSON, &macJSON, &osName, &arch, &clientIP, &currentStatus)
	if err != nil {
		return fmt.Errorf("request not found: %s", id)
	}
	if !currentStatus.Valid || currentStatus.String != string(types.StatusPending) {
		return fmt.Errorf("request is not pending: current status is %s", currentStatus.String)
	}

	now := time.Now()
	tokenJSON, _ := json.Marshal(token)

	_, err = s.db.Exec(`
		UPDATE machine_requests SET
			status = ?, approved_by = ?, approved_at = ?, updated_at = ?, token = ?
		WHERE id = ?`,
		string(types.StatusApproved), approvedBy, now, now, string(tokenJSON), id,
	)
	if err != nil {
		return err
	}

	// Add audit entry
	var tokenID string
	if token != nil {
		tokenID = token.TokenID
	}
	s.db.Exec(`
		INSERT INTO audit_log (timestamp, event_type, request_id, hostname, machine_id,
			ip_addresses, mac_addresses, os, arch, performed_by, token_id, client_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now, string(types.AuditEventApproval), id, hostname.String, machineID.String,
		ipJSON.String, macJSON.String, osName.String, arch.String, approvedBy, tokenID, clientIP.String,
	)

	return nil
}

// ClearToken removes the token from an approved request
func (s *SQLiteStore) ClearToken(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.db.Exec(`UPDATE machine_requests SET token = NULL WHERE id = ?`, id)
}

// ResetToPending resets an approved request back to pending status
func (s *SQLiteStore) ResetToPending(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.db.Exec(`
		UPDATE machine_requests SET
			status = ?, token = NULL, approved_by = '', approved_at = NULL, updated_at = ?
		WHERE id = ?`,
		string(types.StatusPending), now, id,
	)
}

// ClaimToken atomically claims a token for delivery (prevents race conditions)
// Returns the token if available and status was approved, nil otherwise
// After claiming, the token is cleared and status reset to pending
func (s *SQLiteStore) ClaimToken(id string) *types.BootstrapToken {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the token if status is approved
	var tokenJSON sql.NullString
	var status sql.NullString
	err := s.db.QueryRow(`SELECT status, token FROM machine_requests WHERE id = ?`, id).Scan(&status, &tokenJSON)
	if err != nil {
		return nil
	}

	// Only claim if status is approved and token exists
	if !status.Valid || status.String != string(types.StatusApproved) {
		return nil
	}
	if !tokenJSON.Valid || tokenJSON.String == "" || tokenJSON.String == "null" {
		return nil
	}

	// Parse the token
	var token types.BootstrapToken
	if err := json.Unmarshal([]byte(tokenJSON.String), &token); err != nil {
		return nil
	}

	// Atomically clear the token and reset to pending
	now := time.Now()
	_, err = s.db.Exec(`
		UPDATE machine_requests SET
			status = ?, token = NULL, approved_by = '', approved_at = NULL, updated_at = ?
		WHERE id = ? AND status = ? AND token IS NOT NULL`,
		string(types.StatusPending), now, id, string(types.StatusApproved),
	)
	if err != nil {
		return nil
	}

	return &token
}

// Deny marks a request as denied
func (s *SQLiteStore) Deny(id string, deniedBy string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the request for audit log
	row := s.db.QueryRow(`SELECT hostname, machine_id, ip_addresses, mac_addresses, os, arch, client_ip, status
		FROM machine_requests WHERE id = ?`, id)
	var hostname, machineID, ipJSON, macJSON, osName, arch, clientIP, currentStatus sql.NullString
	err := row.Scan(&hostname, &machineID, &ipJSON, &macJSON, &osName, &arch, &clientIP, &currentStatus)
	if err != nil {
		return fmt.Errorf("request not found: %s", id)
	}
	if !currentStatus.Valid || currentStatus.String != string(types.StatusPending) {
		return fmt.Errorf("request is not pending: current status is %s", currentStatus.String)
	}

	now := time.Now()
	_, err = s.db.Exec(`
		UPDATE machine_requests SET
			status = ?, denied_by = ?, denied_at = ?, denial_reason = ?, updated_at = ?
		WHERE id = ?`,
		string(types.StatusDenied), deniedBy, now, reason, now, id,
	)
	if err != nil {
		return err
	}

	// Add audit entry
	s.db.Exec(`
		INSERT INTO audit_log (timestamp, event_type, request_id, hostname, machine_id,
			ip_addresses, mac_addresses, os, arch, performed_by, reason, client_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now, string(types.AuditEventDenial), id, hostname.String, machineID.String,
		ipJSON.String, macJSON.String, osName.String, arch.String, deniedBy, reason, clientIP.String,
	)

	return nil
}

// Delete removes a request
func (s *SQLiteStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Delete from mac_index first (foreign key)
	s.db.Exec(`DELETE FROM mac_index WHERE request_id = ?`, id)

	result, err := s.db.Exec(`DELETE FROM machine_requests WHERE id = ?`, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("request not found: %s", id)
	}

	return nil
}

// UpdateNonce updates the last nonce for a request (for TPM verification)
func (s *SQLiteStore) UpdateNonce(id string, nonce []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`
		UPDATE machine_requests SET last_nonce = ?
		WHERE id = ?`, nonce, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("request not found: %s", id)
	}

	return nil
}

// UpdateTPMVerification updates TPM verification status and errors
func (s *SQLiteStore) UpdateTPMVerification(id string, verified bool, errors []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// First, get the current tpm_attestation
	var tpmJSON sql.NullString
	err := s.db.QueryRow(`SELECT tpm_attestation FROM machine_requests WHERE id = ?`, id).Scan(&tpmJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("request not found: %s", id)
		}
		return err
	}

	if !tpmJSON.Valid || tpmJSON.String == "" {
		return fmt.Errorf("no TPM attestation data for request: %s", id)
	}

	// Parse, update, and re-serialize the TPM attestation
	var attestation types.TPMAttestation
	if err := json.Unmarshal([]byte(tpmJSON.String), &attestation); err != nil {
		return fmt.Errorf("failed to parse TPM attestation: %w", err)
	}

	attestation.Verified = verified
	attestation.VerifyErrors = errors

	updatedJSON, err := json.Marshal(&attestation)
	if err != nil {
		return fmt.Errorf("failed to serialize TPM attestation: %w", err)
	}

	_, err = s.db.Exec(`UPDATE machine_requests SET tpm_attestation = ? WHERE id = ?`, string(updatedJSON), id)
	return err
}

// CleanupExpired removes requests older than the given TTL
func (s *SQLiteStore) CleanupExpired(ttl time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-ttl)
	oldCutoff := time.Now().Add(-7 * 24 * time.Hour)

	// Mark pending requests as expired
	s.db.Exec(`
		UPDATE machine_requests SET status = ?
		WHERE status = ? AND created_at < ?`,
		string(types.StatusExpired), string(types.StatusPending), cutoff,
	)

	// Delete old approved/denied/expired requests
	result, _ := s.db.Exec(`
		DELETE FROM machine_requests
		WHERE (status IN (?, ?, ?) AND updated_at < ?)`,
		string(types.StatusApproved), string(types.StatusDenied), string(types.StatusExpired), oldCutoff,
	)

	// Clean up orphaned MAC index entries
	s.db.Exec(`DELETE FROM mac_index WHERE request_id NOT IN (SELECT id FROM machine_requests)`)

	rows, _ := result.RowsAffected()
	return int(rows)
}

// Stats returns dashboard statistics
func (s *SQLiteStore) Stats() *types.DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.DashboardStats{}

	s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests`).Scan(&stats.TotalRequests)
	s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests WHERE status = ?`, string(types.StatusPending)).Scan(&stats.PendingRequests)
	s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests WHERE status = ?`, string(types.StatusApproved)).Scan(&stats.ApprovedRequests)
	s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests WHERE status = ?`, string(types.StatusDenied)).Scan(&stats.DeniedRequests)
	s.db.QueryRow(`SELECT COUNT(*) FROM machine_requests WHERE status = ?`, string(types.StatusExpired)).Scan(&stats.ExpiredRequests)

	return stats
}

// GetQueuePosition returns the position of a request in the pending queue
func (s *SQLiteStore) GetQueuePosition(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all pending requests sorted by creation time
	rows, err := s.db.Query(`
		SELECT id FROM machine_requests
		WHERE status = ?
		ORDER BY created_at ASC`, string(types.StatusPending))
	if err != nil {
		return 0
	}
	defer rows.Close()

	position := 0
	for rows.Next() {
		position++
		var reqID string
		rows.Scan(&reqID)
		if reqID == id {
			return position
		}
	}

	return 0
}

// --- Agent Registration Methods ---

// UpsertRegistration adds or updates an agent registration
func (s *SQLiteStore) UpsertRegistration(reg *types.AgentRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Check if registration exists
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM agent_registrations WHERE agent_id = ?`, reg.AgentID).Scan(&count)

	ipJSON, _ := json.Marshal(reg.IPAddresses)
	macJSON, _ := json.Marshal(reg.MACAddresses)
	caJSON, _ := json.Marshal(reg.CAStatus)
	powVerJSON, _ := json.Marshal(reg.PoWVerification)
	secureHBJSON, _ := json.Marshal(reg.SecureHeartbeat)

	if count > 0 {
		// Update existing
		_, err := s.db.Exec(`
			UPDATE agent_registrations SET
				hostname = ?, ip_addresses = ?, mac_addresses = ?, os = ?, os_version = ?,
				arch = ?, agent_version = ?, uptime_seconds = ?, binary_path = ?, working_dir = ?,
				ca_status = ?, timestamp = ?, client_ip = ?,
				last_seen_at = ?, register_count = register_count + 1,
				cert_verified = ?, cert_identity = ?,
				pow_status = ?, pow_verification = ?, secure_heartbeat = ?
			WHERE agent_id = ?`,
			reg.Hostname, string(ipJSON), string(macJSON), reg.OS, reg.OSVersion,
			reg.Arch, reg.AgentVersion, reg.UptimeSeconds, reg.BinaryPath, reg.WorkingDir,
			string(caJSON), reg.Timestamp, reg.ClientIP,
			now, reg.CertVerified, reg.CertIdentity,
			reg.PoWStatus, string(powVerJSON), string(secureHBJSON), reg.AgentID,
		)
		return err
	}

	// Insert new
	_, err := s.db.Exec(`
		INSERT INTO agent_registrations (
			agent_id, hostname, ip_addresses, mac_addresses, os, os_version,
			arch, agent_version, uptime_seconds, binary_path, working_dir,
			ca_status, timestamp, client_ip, received_at, last_seen_at, register_count,
			cert_verified, cert_identity, pow_status, pow_verification, secure_heartbeat
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
		reg.AgentID, reg.Hostname, string(ipJSON), string(macJSON), reg.OS, reg.OSVersion,
		reg.Arch, reg.AgentVersion, reg.UptimeSeconds, reg.BinaryPath, reg.WorkingDir,
		string(caJSON), reg.Timestamp, reg.ClientIP, now, now,
		reg.CertVerified, reg.CertIdentity,
		reg.PoWStatus, string(powVerJSON), string(secureHBJSON),
	)
	return err
}

// GetRegistration retrieves a registration by agent ID
func (s *SQLiteStore) GetRegistration(agentID string) (*types.AgentRegistration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`SELECT * FROM agent_registrations WHERE agent_id = ?`, agentID)
	return s.scanRegistration(row)
}

// scanRegistration scans a row into an AgentRegistration
func (s *SQLiteStore) scanRegistration(row *sql.Row) (*types.AgentRegistration, error) {
	var reg types.AgentRegistration
	var ipJSON, macJSON, caJSON string
	var certIdentity, powStatus, powVerJSON, secureHBJSON sql.NullString
	var mqttConnected bool // Legacy column, ignored

	err := row.Scan(
		&reg.AgentID, &reg.Hostname, &ipJSON, &macJSON, &reg.OS, &reg.OSVersion,
		&reg.Arch, &reg.AgentVersion, &reg.UptimeSeconds, &reg.BinaryPath, &reg.WorkingDir,
		&caJSON, &mqttConnected, &reg.Timestamp, &reg.ClientIP,
		&reg.ReceivedAt, &reg.LastSeenAt, &reg.RegisterCount,
		&reg.CertVerified, &certIdentity,
		&powStatus, &powVerJSON, &secureHBJSON,
	)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(ipJSON), &reg.IPAddresses)
	json.Unmarshal([]byte(macJSON), &reg.MACAddresses)
	json.Unmarshal([]byte(caJSON), &reg.CAStatus)
	if certIdentity.Valid {
		reg.CertIdentity = certIdentity.String
	}
	if powStatus.Valid {
		reg.PoWStatus = powStatus.String
	} else {
		reg.PoWStatus = "disabled"
	}
	if powVerJSON.Valid && powVerJSON.String != "" && powVerJSON.String != "null" {
		json.Unmarshal([]byte(powVerJSON.String), &reg.PoWVerification)
	}
	if secureHBJSON.Valid && secureHBJSON.String != "" && secureHBJSON.String != "null" {
		json.Unmarshal([]byte(secureHBJSON.String), &reg.SecureHeartbeat)
	}

	return &reg, nil
}

// deduplicatedQuery returns the SQL for selecting only the most recent registration per hostname
const deduplicatedQuery = `
	SELECT * FROM agent_registrations r1
	WHERE r1.agent_id = (
		SELECT r2.agent_id FROM agent_registrations r2
		WHERE COALESCE(NULLIF(r2.hostname, ''), r2.agent_id) = COALESCE(NULLIF(r1.hostname, ''), r1.agent_id)
		ORDER BY r2.last_seen_at DESC
		LIMIT 1
	)
	ORDER BY r1.last_seen_at DESC
`

// ListRegistrations returns all registrations deduplicated by hostname, sorted by last seen (newest first)
func (s *SQLiteStore) ListRegistrations() []*types.AgentRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(deduplicatedQuery)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []*types.AgentRegistration
	for rows.Next() {
		var reg types.AgentRegistration
		var ipJSON, macJSON, caJSON string
		var certIdentity, powStatus, powVerJSON, secureHBJSON sql.NullString
		var mqttConnected bool // Legacy column, ignored

		err := rows.Scan(
			&reg.AgentID, &reg.Hostname, &ipJSON, &macJSON, &reg.OS, &reg.OSVersion,
			&reg.Arch, &reg.AgentVersion, &reg.UptimeSeconds, &reg.BinaryPath, &reg.WorkingDir,
			&caJSON, &mqttConnected, &reg.Timestamp, &reg.ClientIP,
			&reg.ReceivedAt, &reg.LastSeenAt, &reg.RegisterCount,
			&reg.CertVerified, &certIdentity,
			&powStatus, &powVerJSON, &secureHBJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(ipJSON), &reg.IPAddresses)
		json.Unmarshal([]byte(macJSON), &reg.MACAddresses)
		json.Unmarshal([]byte(caJSON), &reg.CAStatus)
		if certIdentity.Valid {
			reg.CertIdentity = certIdentity.String
		}
		if powStatus.Valid {
			reg.PoWStatus = powStatus.String
		} else {
			reg.PoWStatus = "disabled"
		}
		if powVerJSON.Valid && powVerJSON.String != "" && powVerJSON.String != "null" {
			json.Unmarshal([]byte(powVerJSON.String), &reg.PoWVerification)
		}
		if secureHBJSON.Valid && secureHBJSON.String != "" && secureHBJSON.String != "null" {
			json.Unmarshal([]byte(secureHBJSON.String), &reg.SecureHeartbeat)
		}

		results = append(results, &reg)
	}

	return results
}

// ListRegistrationsPaginated returns paginated registrations deduplicated by hostname, sorted by last seen (newest first)
func (s *SQLiteStore) ListRegistrationsPaginated(params PaginationParams) *PaginatedRegistrations {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get total count of unique hostnames
	var total int
	err := s.db.QueryRow(`SELECT COUNT(DISTINCT COALESCE(NULLIF(hostname, ''), agent_id)) FROM agent_registrations`).Scan(&total)
	if err != nil {
		return &PaginatedRegistrations{Data: []*types.AgentRegistration{}, Total: 0, Offset: params.Offset, Limit: params.Limit}
	}

	// Build deduplicated query with pagination
	query := `
		SELECT * FROM agent_registrations r1
		WHERE r1.agent_id = (
			SELECT r2.agent_id FROM agent_registrations r2
			WHERE COALESCE(NULLIF(r2.hostname, ''), r2.agent_id) = COALESCE(NULLIF(r1.hostname, ''), r1.agent_id)
			ORDER BY r2.last_seen_at DESC
			LIMIT 1
		)
		ORDER BY r1.last_seen_at DESC
	`
	var rows *sql.Rows
	if params.Limit > 0 {
		query += ` LIMIT ? OFFSET ?`
		rows, err = s.db.Query(query, params.Limit, params.Offset)
	} else {
		rows, err = s.db.Query(query)
	}
	if err != nil {
		return &PaginatedRegistrations{Data: []*types.AgentRegistration{}, Total: total, Offset: params.Offset, Limit: params.Limit}
	}
	defer rows.Close()

	var results []*types.AgentRegistration
	for rows.Next() {
		var reg types.AgentRegistration
		var ipJSON, macJSON, caJSON string
		var certIdentity, powStatus, powVerJSON, secureHBJSON sql.NullString
		var mqttConnected bool // Legacy column, ignored

		err := rows.Scan(
			&reg.AgentID, &reg.Hostname, &ipJSON, &macJSON, &reg.OS, &reg.OSVersion,
			&reg.Arch, &reg.AgentVersion, &reg.UptimeSeconds, &reg.BinaryPath, &reg.WorkingDir,
			&caJSON, &mqttConnected, &reg.Timestamp, &reg.ClientIP,
			&reg.ReceivedAt, &reg.LastSeenAt, &reg.RegisterCount,
			&reg.CertVerified, &certIdentity,
			&powStatus, &powVerJSON, &secureHBJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(ipJSON), &reg.IPAddresses)
		json.Unmarshal([]byte(macJSON), &reg.MACAddresses)
		json.Unmarshal([]byte(caJSON), &reg.CAStatus)
		if certIdentity.Valid {
			reg.CertIdentity = certIdentity.String
		}
		if powStatus.Valid {
			reg.PoWStatus = powStatus.String
		} else {
			reg.PoWStatus = "disabled"
		}
		if powVerJSON.Valid && powVerJSON.String != "" && powVerJSON.String != "null" {
			json.Unmarshal([]byte(powVerJSON.String), &reg.PoWVerification)
		}
		if secureHBJSON.Valid && secureHBJSON.String != "" && secureHBJSON.String != "null" {
			json.Unmarshal([]byte(secureHBJSON.String), &reg.SecureHeartbeat)
		}

		results = append(results, &reg)
	}

	return &PaginatedRegistrations{
		Data:   results,
		Total:  total,
		Offset: params.Offset,
		Limit:  params.Limit,
	}
}

// CountRegistrations returns the total number of unique agents (deduplicated by hostname)
func (s *SQLiteStore) CountRegistrations() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow(`SELECT COUNT(DISTINCT COALESCE(NULLIF(hostname, ''), agent_id)) FROM agent_registrations`).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// DeleteRegistration removes a registration
func (s *SQLiteStore) DeleteRegistration(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`DELETE FROM agent_registrations WHERE agent_id = ?`, agentID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("registration not found: %s", agentID)
	}

	return nil
}

// SystemStats returns statistics about registered agents (deduplicated by hostname)
func (s *SQLiteStore) SystemStats() *types.SystemStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.SystemStats{}
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	// Deduplicated counts using subquery to get only the most recent registration per hostname
	// Total unique agents
	s.db.QueryRow(`SELECT COUNT(DISTINCT COALESCE(NULLIF(hostname, ''), agent_id)) FROM agent_registrations`).Scan(&stats.TotalAgents)

	// Active agents (seen in last 5 minutes) - count unique hostnames where most recent registration is active
	s.db.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT COALESCE(NULLIF(hostname, ''), agent_id) as host_key, MAX(last_seen_at) as max_seen
			FROM agent_registrations
			GROUP BY host_key
			HAVING max_seen > ?
		)`, fiveMinutesAgo).Scan(&stats.ActiveAgents)

	// CA ready agents - count unique hostnames where most recent registration has CA ready
	s.db.QueryRow(`
		SELECT COUNT(*) FROM agent_registrations r1
		WHERE r1.agent_id = (
			SELECT r2.agent_id FROM agent_registrations r2
			WHERE COALESCE(NULLIF(r2.hostname, ''), r2.agent_id) = COALESCE(NULLIF(r1.hostname, ''), r1.agent_id)
			ORDER BY r2.last_seen_at DESC
			LIMIT 1
		)
		AND r1.ca_status LIKE '%"ready":true%'
	`).Scan(&stats.CAReadyAgents)

	return stats
}

// --- Audit Log Methods ---

// AddAuditEntry adds an entry to the audit log
func (s *SQLiteStore) AddAuditEntry(entry *types.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipJSON, _ := json.Marshal(entry.IPAddresses)
	macJSON, _ := json.Marshal(entry.MACAddresses)

	_, err := s.db.Exec(`
		INSERT INTO audit_log (timestamp, event_type, request_id, hostname, machine_id,
			ip_addresses, mac_addresses, os, arch, performed_by, reason, token_id, client_ip, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, string(entry.EventType), entry.RequestID, entry.Hostname, entry.MachineID,
		string(ipJSON), string(macJSON), entry.OS, entry.Arch, entry.PerformedBy, entry.Reason,
		entry.TokenID, entry.ClientIP, entry.Details,
	)
	return err
}

// ListAuditLog returns audit entries, newest first, with optional limit
func (s *SQLiteStore) ListAuditLog(limit int) []*types.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, timestamp, event_type, request_id, hostname, machine_id,
		ip_addresses, mac_addresses, os, arch, performed_by, reason, token_id, client_ip, details
		FROM audit_log ORDER BY timestamp DESC`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query)
	if err != nil {
		fmt.Printf("[SQLite] ListAuditLog query error: %v\n", err)
		return nil
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// ListAuditLogByHostname returns audit entries for a specific hostname
func (s *SQLiteStore) ListAuditLogByHostname(hostname string, limit int) []*types.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, timestamp, event_type, request_id, hostname, machine_id,
		ip_addresses, mac_addresses, os, arch, performed_by, reason, token_id, client_ip, details
		FROM audit_log WHERE hostname = ? ORDER BY timestamp DESC`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, hostname)
	if err != nil {
		return nil
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// ListAuditLogByEventType returns audit entries of a specific type
func (s *SQLiteStore) ListAuditLogByEventType(eventType types.AuditEventType, limit int) []*types.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, timestamp, event_type, request_id, hostname, machine_id,
		ip_addresses, mac_addresses, os, arch, performed_by, reason, token_id, client_ip, details
		FROM audit_log WHERE event_type = ? ORDER BY timestamp DESC`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, string(eventType))
	if err != nil {
		return nil
	}
	defer rows.Close()

	return s.scanAuditEntries(rows)
}

// scanAuditEntries scans multiple audit log rows
func (s *SQLiteStore) scanAuditEntries(rows *sql.Rows) []*types.AuditEntry {
	var results []*types.AuditEntry

	for rows.Next() {
		var entry types.AuditEntry
		var eventType string
		var requestID, hostname, machineID, ipJSON, macJSON sql.NullString
		var os, arch, performedBy, reason, tokenID, clientIP, details sql.NullString

		err := rows.Scan(
			&entry.ID, &entry.Timestamp, &eventType, &requestID, &hostname, &machineID,
			&ipJSON, &macJSON, &os, &arch, &performedBy, &reason, &tokenID, &clientIP, &details,
		)
		if err != nil {
			fmt.Printf("[SQLite] scanAuditEntries error: %v\n", err)
			continue
		}

		entry.EventType = types.AuditEventType(eventType)
		entry.RequestID = requestID.String
		entry.Hostname = hostname.String
		entry.MachineID = machineID.String
		entry.OS = os.String
		entry.Arch = arch.String
		entry.PerformedBy = performedBy.String
		entry.Reason = reason.String
		entry.TokenID = tokenID.String
		entry.ClientIP = clientIP.String
		entry.Details = details.String

		if ipJSON.Valid {
			json.Unmarshal([]byte(ipJSON.String), &entry.IPAddresses)
		}
		if macJSON.Valid {
			json.Unmarshal([]byte(macJSON.String), &entry.MACAddresses)
		}

		results = append(results, &entry)
	}

	return results
}

// --- Alert Methods ---

// AddAlert adds a new alert
func (s *SQLiteStore) AddAlert(alert *types.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alert.ID == "" {
		alert.ID = generateAlertID()
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = time.Now()
	}

	_, err := s.db.Exec(`
		INSERT INTO alerts (id, created_at, type, severity, agent_id, hostname, agent_version,
			message, details, old_version, new_version, last_seen_at, stale_duration_min,
			acknowledged, acknowledged_by, acknowledged_at, resolved, resolved_by, resolved_at, resolution)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		alert.ID, alert.CreatedAt, string(alert.Type), string(alert.Severity),
		alert.AgentID, alert.Hostname, alert.AgentVersion,
		alert.Message, alert.Details, alert.OldVersion, alert.NewVersion,
		alert.LastSeenAt, alert.StaleDurationMin,
		alert.Acknowledged, alert.AcknowledgedBy, alert.AcknowledgedAt,
		alert.Resolved, alert.ResolvedBy, alert.ResolvedAt, alert.Resolution,
	)
	return err
}

// generateAlertID creates a unique alert ID
func generateAlertID() string {
	return fmt.Sprintf("alert-%d", time.Now().UnixNano())
}

// GetAlert retrieves an alert by ID
func (s *SQLiteStore) GetAlert(id string) (*types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getAlertByID(id)
}

func (s *SQLiteStore) getAlertByID(id string) (*types.Alert, error) {
	var alert types.Alert
	var alertType, severity string
	var agentVersion, details, oldVersion, newVersion, acknowledgedBy, resolvedBy, resolution sql.NullString
	var lastSeenAt, acknowledgedAt, resolvedAt sql.NullTime
	var staleDurationMin sql.NullInt64

	err := s.db.QueryRow(`
		SELECT id, created_at, type, severity, agent_id, hostname, agent_version,
			message, details, old_version, new_version, last_seen_at, stale_duration_min,
			acknowledged, acknowledged_by, acknowledged_at, resolved, resolved_by, resolved_at, resolution
		FROM alerts WHERE id = ?`, id).Scan(
		&alert.ID, &alert.CreatedAt, &alertType, &severity,
		&alert.AgentID, &alert.Hostname, &agentVersion,
		&alert.Message, &details, &oldVersion, &newVersion,
		&lastSeenAt, &staleDurationMin,
		&alert.Acknowledged, &acknowledgedBy, &acknowledgedAt,
		&alert.Resolved, &resolvedBy, &resolvedAt, &resolution,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("alert not found: %s", id)
		}
		return nil, err
	}

	alert.Type = types.AlertType(alertType)
	alert.Severity = types.AlertSeverity(severity)
	alert.AgentVersion = agentVersion.String
	alert.Details = details.String
	alert.OldVersion = oldVersion.String
	alert.NewVersion = newVersion.String
	alert.AcknowledgedBy = acknowledgedBy.String
	alert.ResolvedBy = resolvedBy.String
	alert.Resolution = resolution.String

	if lastSeenAt.Valid {
		alert.LastSeenAt = &lastSeenAt.Time
	}
	if acknowledgedAt.Valid {
		alert.AcknowledgedAt = &acknowledgedAt.Time
	}
	if resolvedAt.Valid {
		alert.ResolvedAt = &resolvedAt.Time
	}
	if staleDurationMin.Valid {
		alert.StaleDurationMin = int(staleDurationMin.Int64)
	}

	return &alert, nil
}

// ListAlerts returns all alerts, sorted by creation time (newest first)
func (s *SQLiteStore) ListAlerts() []*types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, created_at, type, severity, agent_id, hostname, agent_version,
			message, details, old_version, new_version, last_seen_at, stale_duration_min,
			acknowledged, acknowledged_by, acknowledged_at, resolved, resolved_by, resolved_at, resolution
		FROM alerts ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	return s.scanAlerts(rows)
}

// ListUnacknowledgedAlerts returns alerts that haven't been acknowledged
func (s *SQLiteStore) ListUnacknowledgedAlerts() []*types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, created_at, type, severity, agent_id, hostname, agent_version,
			message, details, old_version, new_version, last_seen_at, stale_duration_min,
			acknowledged, acknowledged_by, acknowledged_at, resolved, resolved_by, resolved_at, resolution
		FROM alerts WHERE acknowledged = FALSE ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	return s.scanAlerts(rows)
}

// ListAlertsByType returns alerts of a specific type
func (s *SQLiteStore) ListAlertsByType(alertType types.AlertType) []*types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, created_at, type, severity, agent_id, hostname, agent_version,
			message, details, old_version, new_version, last_seen_at, stale_duration_min,
			acknowledged, acknowledged_by, acknowledged_at, resolved, resolved_by, resolved_at, resolution
		FROM alerts WHERE type = ? ORDER BY created_at DESC`, string(alertType))
	if err != nil {
		return nil
	}
	defer rows.Close()

	return s.scanAlerts(rows)
}

// scanAlerts scans rows into Alert structs
func (s *SQLiteStore) scanAlerts(rows *sql.Rows) []*types.Alert {
	var results []*types.Alert

	for rows.Next() {
		var alert types.Alert
		var alertType, severity string
		var agentVersion, details, oldVersion, newVersion, acknowledgedBy, resolvedBy, resolution sql.NullString
		var lastSeenAt, acknowledgedAt, resolvedAt sql.NullTime
		var staleDurationMin sql.NullInt64

		err := rows.Scan(
			&alert.ID, &alert.CreatedAt, &alertType, &severity,
			&alert.AgentID, &alert.Hostname, &agentVersion,
			&alert.Message, &details, &oldVersion, &newVersion,
			&lastSeenAt, &staleDurationMin,
			&alert.Acknowledged, &acknowledgedBy, &acknowledgedAt,
			&alert.Resolved, &resolvedBy, &resolvedAt, &resolution,
		)
		if err != nil {
			continue
		}

		alert.Type = types.AlertType(alertType)
		alert.Severity = types.AlertSeverity(severity)
		alert.AgentVersion = agentVersion.String
		alert.Details = details.String
		alert.OldVersion = oldVersion.String
		alert.NewVersion = newVersion.String
		alert.AcknowledgedBy = acknowledgedBy.String
		alert.ResolvedBy = resolvedBy.String
		alert.Resolution = resolution.String

		if lastSeenAt.Valid {
			alert.LastSeenAt = &lastSeenAt.Time
		}
		if acknowledgedAt.Valid {
			alert.AcknowledgedAt = &acknowledgedAt.Time
		}
		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}
		if staleDurationMin.Valid {
			alert.StaleDurationMin = int(staleDurationMin.Int64)
		}

		results = append(results, &alert)
	}

	return results
}

// AcknowledgeAlert marks an alert as acknowledged
func (s *SQLiteStore) AcknowledgeAlert(id string, acknowledgedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`
		UPDATE alerts SET acknowledged = TRUE, acknowledged_by = ?, acknowledged_at = ?
		WHERE id = ?`,
		acknowledgedBy, time.Now(), id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("alert not found: %s", id)
	}
	return nil
}

// ResolveAlert marks an alert as resolved
func (s *SQLiteStore) ResolveAlert(id string, resolvedBy string, resolution string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`
		UPDATE alerts SET resolved = TRUE, resolved_by = ?, resolved_at = ?, resolution = ?
		WHERE id = ?`,
		resolvedBy, time.Now(), resolution, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("alert not found: %s", id)
	}
	return nil
}

// DeleteAlert removes an alert
func (s *SQLiteStore) DeleteAlert(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(`DELETE FROM alerts WHERE id = ?`, id)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("alert not found: %s", id)
	}
	return nil
}

// AlertStats returns statistics about alerts
func (s *SQLiteStore) AlertStats() *types.AlertStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &types.AlertStats{}

	s.db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&stats.TotalAlerts)
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE acknowledged = FALSE`).Scan(&stats.UnacknowledgedCount)
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE type = 'stale_agent'`).Scan(&stats.StaleAgentCount)
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE type = 'version_change'`).Scan(&stats.VersionChangeCount)

	return stats
}

// GetAlertByAgentVersion returns an alert for a specific agent ID and version
func (s *SQLiteStore) GetAlertByAgentVersion(agentID string, version string) (*types.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var alertID string
	err := s.db.QueryRow(`SELECT id FROM alerts WHERE agent_id = ? AND agent_version = ?`, agentID, version).Scan(&alertID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("alert not found for agent %s version %s", agentID, version)
		}
		return nil, err
	}

	return s.getAlertByID(alertID)
}

// GetAllRegistrationsByHostname returns all registrations for a hostname (including old versions)
func (s *SQLiteStore) GetAllRegistrationsByHostname(hostname string) []*types.AgentRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT agent_id, hostname, ip_addresses, mac_addresses, os, os_version,
			arch, agent_version, uptime_seconds, binary_path, working_dir,
			ca_status, mqtt_connected, timestamp, client_ip,
			received_at, last_seen_at, register_count, cert_verified, cert_identity,
			pow_status, pow_verification, secure_heartbeat
		FROM agent_registrations WHERE hostname = ? ORDER BY last_seen_at DESC`, hostname)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []*types.AgentRegistration
	for rows.Next() {
		var reg types.AgentRegistration
		var ipJSON, macJSON, caJSON string
		var certIdentity, powStatus, powVerJSON, secureHBJSON sql.NullString
		var mqttConnected bool

		err := rows.Scan(
			&reg.AgentID, &reg.Hostname, &ipJSON, &macJSON, &reg.OS, &reg.OSVersion,
			&reg.Arch, &reg.AgentVersion, &reg.UptimeSeconds, &reg.BinaryPath, &reg.WorkingDir,
			&caJSON, &mqttConnected, &reg.Timestamp, &reg.ClientIP,
			&reg.ReceivedAt, &reg.LastSeenAt, &reg.RegisterCount,
			&reg.CertVerified, &certIdentity,
			&powStatus, &powVerJSON, &secureHBJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(ipJSON), &reg.IPAddresses)
		json.Unmarshal([]byte(macJSON), &reg.MACAddresses)
		json.Unmarshal([]byte(caJSON), &reg.CAStatus)
		if certIdentity.Valid {
			reg.CertIdentity = certIdentity.String
		}
		if powStatus.Valid {
			reg.PoWStatus = powStatus.String
		} else {
			reg.PoWStatus = "disabled"
		}
		if powVerJSON.Valid && powVerJSON.String != "" && powVerJSON.String != "null" {
			json.Unmarshal([]byte(powVerJSON.String), &reg.PoWVerification)
		}
		if secureHBJSON.Valid && secureHBJSON.String != "" && secureHBJSON.String != "null" {
			json.Unmarshal([]byte(secureHBJSON.String), &reg.SecureHeartbeat)
		}

		results = append(results, &reg)
	}

	return results
}

// Verify SQLiteStore implements Store interface
var _ Store = (*SQLiteStore)(nil)

// Also verify MemoryStore implements Store interface
var _ Store = (*MemoryStore)(nil)
