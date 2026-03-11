# MID System Overview

## Introduction

MID (Machine Identity) is a system for automated machine identity provisioning and management. It provides secure, operator-controlled enrollment of machines into a SPIFFE-based identity framework, using HashiCorp Vault as the PKI backend.

## Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OPERATOR                                        │
│                                 │                                            │
│                          Approve/Deny                                        │
│                                 ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                     MID Bootstrap Server                              │   │
│  │                    (Approval Workflow)                                │   │
│  │  - Web Dashboard for operator approval                                │   │
│  │  - Tracks machine enrollment requests                                 │   │
│  │  - Generates one-time bootstrap tokens                                │   │
│  │  - Agent registration/heartbeat tracking                              │   │
│  │  - Audit logging for compliance                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                 │                                            │
│                    POST /v1/auth/mid/tokens/generate                         │
│                                 ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      HashiCorp Vault                                  │   │
│  │  ┌────────────────────┐    ┌────────────────────┐                    │   │
│  │  │  vault-secrets-mid │    │    pki-mid-auth    │                    │   │
│  │  │  (Token Generator) │    │  (Cert Auth/Issue) │                    │   │
│  │  │                    │    │                    │                    │   │
│  │  │ - Generate tokens  │    │ - Validate tokens  │                    │   │
│  │  │ - One-time use     │    │ - Issue certs      │                    │   │
│  │  │ - TTL-based expiry │    │ - Cert renewal     │                    │   │
│  │  └────────────────────┘    └────────────────────┘                    │   │
│  │                                    │                                  │   │
│  │                              PKI Backend                              │   │
│  │                     (Intermediate CA Certificates)                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                 ▲                                            │
│              POST /v1/auth/mid/login (token + hostname)                      │
│              POST /v1/pki/issue/role (CSR)                                   │
│                                 │                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         MID Agent (MAG)                              │   │
│  │                    (runs on each machine)                             │   │
│  │                                                                       │   │
│  │  - Auto-bootstrap client (polls bootstrap server)                     │   │
│  │  - SPIFFE Workload API provider                                       │   │
│  │  - Local CA for workload certificates                                 │   │
│  │  - Certificate renewal                                                │   │
│  │  - Registration heartbeat to bootstrap server                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                 │                                            │
│                    Unix Socket / TCP (localhost only)                        │
│                                 ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        WORKLOADS                                      │   │
│  │              (Applications requesting identity)                       │   │
│  │                                                                       │   │
│  │  - Request X.509 SVIDs via Workload API                              │   │
│  │  - Request JWT SVIDs for service authentication                       │   │
│  │  - mTLS between services                                              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. MID Agent (MAG)

The MID Agent runs on each machine that needs identity provisioning. It provides:

- **Auto-Bootstrap Client**: Periodically polls the bootstrap server for enrollment approval
- **SPIFFE Workload API**: Provides X.509 and JWT SVIDs to local workloads
- **Local CA**: Issues workload certificates using the agent's intermediate CA
- **Certificate Renewal**: Automatically renews certificates before expiry
- **Registration Heartbeat**: Periodically sends status updates to the bootstrap server

**Key Features:**
- In-memory credential storage (no secrets written to disk by default)
- Workload attestation (validates requesting process by UID, PID, path, etc.)
- Selector-based identity assignment
- mTLS support for registration (proves identity with local CA certificate)

### 2. MID Bootstrap Server

The Bootstrap Server provides an operator-controlled approval workflow for machine enrollment:

- **Web Dashboard**: Visual interface for approving/denying enrollment requests
- **System Dashboard**: View all registered agents and their status
- **Audit Dashboard**: View all approval/denial events for compliance
- **Request Queue**: Tracks pending machines with system info (hostname, IPs, OS, etc.)
- **Token Generation**: Calls vault-secrets-mid to generate one-time bootstrap tokens
- **One-Time Delivery**: Each approval generates exactly one token; re-enrollment requires re-approval
- **Agent Registration**: Receives periodic heartbeats from registered agents
- **Persistent Storage**: SQLite database for requests, registrations, and audit logs

**Key Features:**
- Stateless token delivery (token cleared after delivery)
- Machine tracking by hostname and MAC address
- Optional TPM attestation support
- Auto-approval options: trusted network, TPM attestation, reverse DNS
- mTLS verification for agent registrations
- Full audit logging for compliance

### 3. vault-secrets-mid (Vault Plugin)

A Vault secrets engine plugin that generates one-time bootstrap tokens:

- **Token Generation**: `POST /v1/auth/mid/tokens/generate`
- **One-Time Use**: Tokens are consumed on first use
- **TTL-Based Expiry**: Unused tokens expire after configured TTL
- **Role-Based**: Tokens are scoped to specific roles

**API:**
```bash
# Generate a bootstrap token
vault write auth/mid/tokens/generate role="vm" agent_id="hostname"
```

### 4. pki-mid-auth (Vault Plugin)

A Vault auth method plugin that handles token-based authentication and certificate issuance:

- **Token Login**: Validates one-time tokens from vault-secrets-mid
- **Certificate Issuance**: Issues intermediate CA certificates to agents
- **Certificate Renewal**: Allows agents to renew using their existing certificate

**API:**
```bash
# Login with bootstrap token (first time)
vault write auth/mid/login token="..." hostname="..."

# Renew certificate (subsequent)
vault write auth/mid/renew certificate="..."
```

## Enrollment Flow

### Initial Bootstrap (Operator Approval Required)

```
┌─────────┐         ┌──────────────┐         ┌───────┐         ┌─────────────┐
│  Agent  │         │  Bootstrap   │         │ Vault │         │  Operator   │
│         │         │   Server     │         │       │         │             │
└────┬────┘         └──────┬───────┘         └───┬───┘         └──────┬──────┘
     │                     │                     │                    │
     │ POST /bootstrap     │                     │                    │
     │ {hostname, IPs...}  │                     │                    │
     │────────────────────>│                     │                    │
     │                     │                     │                    │
     │ {"status":"pending"}│                     │                    │
     │<────────────────────│                     │                    │
     │                     │                     │                    │
     │                     │                     │    View Dashboard  │
     │                     │                     │<───────────────────│
     │                     │                     │                    │
     │                     │                     │   Click "Approve"  │
     │                     │<────────────────────────────────────────│
     │                     │                     │                    │
     │                     │ POST tokens/generate│                    │
     │                     │────────────────────>│                    │
     │                     │                     │                    │
     │                     │ {token, token_id}   │                    │
     │                     │<────────────────────│                    │
     │                     │                     │                    │
     │ (polls again)       │                     │                    │
     │────────────────────>│                     │                    │
     │                     │                     │                    │
     │ {"status":"approved"│                     │                    │
     │  "token":"..."}     │                     │                    │
     │<────────────────────│                     │                    │
     │                     │                     │                    │
     │ POST auth/mid/login │                     │                    │
     │ {token, hostname}   │                     │                    │
     │─────────────────────────────────────────>│                    │
     │                     │                     │                    │
     │ {certificate, key, ca_chain}             │                    │
     │<─────────────────────────────────────────│                    │
     │                     │                     │                    │
     │ [Agent now has intermediate CA]          │                    │
     │ [Can issue workload certificates]        │                    │
     │                     │                     │                    │
```

### Re-Enrollment (After Agent Restart)

Since credentials are stored in memory only, a restarted agent must re-enroll:

1. Agent polls bootstrap server
2. Status is "pending" (reset after previous token delivery)
3. Operator must approve again
4. New token generated and delivered
5. Agent exchanges token for new certificate

This ensures operator visibility and control over all machine enrollments.

## Web Dashboards

The bootstrap server provides three web dashboards:

### 1. Bootstrap Requests Dashboard (`/`)

Main dashboard for managing bootstrap enrollment requests:

- **Stats Overview**: Total, pending, approved, denied request counts
- **Pending Requests**: List of machines waiting for approval with:
  - Hostname, OS, architecture
  - IP addresses, MAC addresses
  - Uptime, TPM status
  - First seen time, request count
  - Approve/Deny buttons
- **Recently Approved**: Machines that have been approved
- **Denied Requests**: Machines that have been denied

### 2. System Dashboard (`/system`)

Dashboard for monitoring registered agents:

- **Stats Overview**: Total agents, active (seen in last 5 min), CA ready, MQTT connected
- **Agent List**: All registered agents with:
  - Agent ID, hostname
  - IP addresses
  - OS, version, architecture
  - CA status (ready/pending, expiry time)
  - MQTT connection status
  - Uptime, last seen time
  - mTLS verification status
- **Search & Filter**: Filter by hostname, status, CA state, MQTT state

### 3. Audit Log Dashboard (`/audit`)

Dashboard for compliance and auditing:

- **Recent Events**: All approval/denial events with:
  - Timestamp
  - Event type (Approval, Denial, Token Delivered, Reset to Pending)
  - Hostname, OS, architecture
  - Performed by (operator username)
  - Token ID (for approvals)
  - Reason (for denials)
- **Search**: Filter by hostname, event type, operator

## API Endpoints

### Bootstrap API (No Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/bootstrap/{os}/machine` | POST | Submit bootstrap request |
| `/health` | GET | Health check |
| `/registration` | POST | Agent registration/heartbeat |

### Admin API (Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/requests` | GET | List all requests |
| `/api/requests?status=pending` | GET | List requests by status |
| `/api/requests/{id}` | GET | Get specific request |
| `/api/requests/{id}` | DELETE | Delete a request |
| `/api/approve` | POST | Approve a request |
| `/api/deny` | POST | Deny a request |
| `/api/stats` | GET | Get dashboard statistics |
| `/api/systems` | GET | List all registered agents |
| `/api/system-stats` | GET | Get agent statistics |
| `/api/audit` | GET | List audit log entries |
| `/api/audit?limit=100` | GET | Limit audit results |
| `/api/audit?hostname=xxx` | GET | Filter by hostname |
| `/api/audit?event_type=approval` | GET | Filter by event type |

## Database Schema

The bootstrap server uses SQLite for persistent storage.

### Machine Requests Table

```sql
CREATE TABLE machine_requests (
    id TEXT PRIMARY KEY,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    hostname TEXT NOT NULL,
    machine_id TEXT,
    ip_addresses TEXT,          -- JSON array
    mac_addresses TEXT,         -- JSON array
    os TEXT,
    arch TEXT,
    os_version TEXT,
    uptime_seconds INTEGER,
    agent_version TEXT,
    has_tpm BOOLEAN DEFAULT FALSE,
    tpm_attestation TEXT,       -- JSON object
    status TEXT NOT NULL,       -- 'pending', 'approved', 'denied', 'expired'
    status_reason TEXT,
    approved_by TEXT,
    approved_at DATETIME,
    denied_by TEXT,
    denied_at DATETIME,
    denial_reason TEXT,
    token TEXT,                 -- JSON object (bootstrap token)
    client_ip TEXT,
    last_seen_at DATETIME,
    request_count INTEGER DEFAULT 1
);

CREATE INDEX idx_hostname ON machine_requests(hostname);
CREATE INDEX idx_status ON machine_requests(status);
CREATE INDEX idx_created_at ON machine_requests(created_at);
```

### MAC Index Table

```sql
CREATE TABLE mac_index (
    mac_address TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES machine_requests(id) ON DELETE CASCADE
);
```

### Agent Registrations Table

```sql
CREATE TABLE agent_registrations (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip_addresses TEXT,          -- JSON array
    mac_addresses TEXT,         -- JSON array
    os TEXT,
    os_version TEXT,
    arch TEXT,
    agent_version TEXT,
    uptime_seconds INTEGER,
    binary_path TEXT,
    working_dir TEXT,
    ca_status TEXT,             -- JSON object
    mqtt_connected BOOLEAN DEFAULT FALSE,
    timestamp DATETIME,
    client_ip TEXT,
    received_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    register_count INTEGER DEFAULT 1,
    cert_verified BOOLEAN DEFAULT FALSE,
    cert_identity TEXT
);

CREATE INDEX idx_reg_hostname ON agent_registrations(hostname);
CREATE INDEX idx_reg_last_seen ON agent_registrations(last_seen_at);
```

### Audit Log Table

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    event_type TEXT NOT NULL,   -- 'approval', 'denial', 'token_delivered', 'reset_to_pending', 'auto_approval'
    request_id TEXT,
    hostname TEXT,
    machine_id TEXT,
    ip_addresses TEXT,          -- JSON array
    mac_addresses TEXT,         -- JSON array
    os TEXT,
    arch TEXT,
    performed_by TEXT,          -- Operator username
    reason TEXT,                -- Denial reason or comment
    token_id TEXT,              -- Token ID if issued
    client_ip TEXT,
    details TEXT                -- JSON object for additional info
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_hostname ON audit_log(hostname);
CREATE INDEX idx_audit_request_id ON audit_log(request_id);
```

## Configuration

### Bootstrap Server (config.json)

```json
{
  "listen_addr": ":8443",
  "tls_cert": "bootstrap-cert.pem",
  "tls_key": "bootstrap-key.pem",
  "tls_min_version": "1.2",

  "vault_addr": "https://vault:8200",
  "vault_ca_cert": "certs/vault-ca.pem",
  "vault_skip_verify": false,

  "bootstrap_type": "token",
  "vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
  "vault_auth_role": "vm",
  "vault_auth_mount": "jwt",

  "trusted_networks": ["192.168.1.0/24"],
  "auto_approve_from_trust": false,
  "auto_approve_tpm": false,
  "auto_approve_dns": false,

  "store_type": "sqlite",
  "store_path": "bootstrap.db",

  "request_ttl": "24h",
  "cleanup_interval": "1h",
  "default_retry_after": 300,

  "web_enabled": true,
  "web_auth_method": "basic",
  "web_auth_realm": "MID Bootstrap Server",
  "web_auth_users": {
    "admin": {
      "password_hash": "sha256-hash-here",
      "roles": ["admin"]
    }
  },

  "registration_require_mtls": false,
  "registration_ca_cert": "certs/agent-ca.pem"
}
```

### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `listen_addr` | string | Server listen address (e.g., ":8443") |
| `tls_cert` | string | Path to TLS certificate |
| `tls_key` | string | Path to TLS private key |
| `tls_min_version` | string | Minimum TLS version ("1.2" or "1.3") |
| `vault_addr` | string | Vault server URL |
| `vault_ca_cert` | string | Path to Vault CA certificate |
| `vault_skip_verify` | bool | Skip Vault TLS verification (insecure) |
| `bootstrap_type` | string | `certificate` (MID auth) or `token` (JWT login) |
| `vault_jwt_source` | string | JWT source: `file:///`, `http://`, `https://`, or `exec:///` |
| `vault_auth_role` | string | Vault role for JWT auth |
| `vault_auth_mount` | string | JWT auth mount path (default: `jwt`) |
| `mid_auth_mount` | string | Vault MID auth mount path (certificate bootstrap only) |
| `mid_role` | string | Vault MID role (certificate bootstrap only) |
| `trusted_networks` | []string | CIDRs for trusted networks |
| `auto_approve_from_trust` | bool | Auto-approve requests from trusted networks |
| `auto_approve_tpm` | bool | Auto-approve when TPM attestation is verified |
| `auto_approve_dns` | bool | Auto-approve when reverse DNS matches hostname |
| `store_type` | string | "memory" or "sqlite" |
| `store_path` | string | Path to SQLite database file |
| `request_ttl` | duration | How long to keep pending requests |
| `cleanup_interval` | duration | How often to clean expired requests |
| `web_enabled` | bool | Enable web dashboard |
| `web_auth_method` | string | "none" or "basic" |
| `web_auth_users` | map | Users for basic auth |
| `registration_require_mtls` | bool | Require client cert for /registration |
| `registration_ca_cert` | string | CA cert for verifying agent client certs |

### MID Agent (mag.conf)

```json
{
  "auto_bootstrap_enabled": true,
  "auto_bootstrap_server_url": "https://bootstrap-server:8443",
  "auto_bootstrap_interval_seconds": 30,
  "auto_bootstrap_jitter_seconds": 5,
  "auto_bootstrap_tls_skip_verify": false,

  "bootstrap_enabled": true,
  "bootstrap_vault_addr": "https://vault:8200",
  "bootstrap_vault_auth_path": "mid",
  "bootstrap_role": "vm",

  "registration_enabled": true,

  "spiffe_enabled": true,
  "spiffe_trust_domain": "example.org",
  "spiffe_local_ca": {
    "enabled": true,
    "vault_addr": "https://vault:8200",
    "vault_pki_mount": "pki",
    "vault_pki_role": "agent",
    "intermediate_ttl": "24h",
    "workload_default_ttl": "1h"
  }
}
```

## Security Model

### Trust Hierarchy

```
Root CA (Vault PKI)
    │
    └── Intermediate CA (per MID Agent)
            │
            └── Workload Certificates (issued by Agent)
```

### Security Properties

1. **One-Time Tokens**: Bootstrap tokens can only be used once
2. **Operator Approval**: Every enrollment requires explicit approval (or auto-approval)
3. **Auto-Approval Options**: TPM attestation, reverse DNS, or trusted network verification
4. **In-Memory Secrets**: Agent credentials not persisted to disk by default
5. **Workload Attestation**: Workloads verified by process attributes
6. **Short-Lived Certificates**: Workload certs have configurable TTL
7. **Automatic Renewal**: Certificates renewed before expiry
8. **mTLS Verification**: Agent registrations can require client certificates
9. **Audit Logging**: All approvals/denials logged for compliance

### Auto-Approval Security Levels

| Method | Security Level | Verification |
|--------|---------------|--------------|
| TPM Attestation | Highest | Hardware-based cryptographic proof |
| Reverse DNS | Medium | DNS infrastructure trust |
| Trusted Network | Lowest | IP address/network only |

Auto-approval methods are evaluated in order: Trusted Network → TPM → DNS. The first matching method approves the request.

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Stolen bootstrap token | One-time use, TTL expiry |
| Rogue machine enrollment | Operator approval or TPM/DNS verification |
| Credential theft from disk | In-memory storage only |
| Workload impersonation | Process attestation (UID, path, etc.) |
| Certificate compromise | Short TTL, automatic renewal |
| Fake registration reports | mTLS verification with agent certificate |
| Unauthorized access | Basic auth on web dashboard |
| Compliance requirements | Full audit logging |

## Operational Considerations

### Scaling

- Bootstrap server supports SQLite for persistence (single instance)
- For high availability, use external database (future enhancement)
- Multiple agents can enroll concurrently
- Vault handles certificate issuance load

### Monitoring

- Bootstrap server logs all approval/denial actions
- Agent logs bootstrap attempts and certificate renewals
- Vault audit logs capture all token and certificate operations
- System dashboard shows agent health at a glance
- Audit log provides compliance trail

### Disaster Recovery

- Agent restart requires re-approval (by design for security)
- SQLite database should be backed up regularly
- Vault is the source of truth for PKI state
- Audit logs preserved in database for compliance

### Maintenance

- Expired requests are automatically cleaned up
- Old approved/denied requests purged after 7 days
- Audit logs are preserved indefinitely
- Database can be vacuumed periodically for performance
