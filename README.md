# MID Bootstrap Server

A bootstrap server for MAG agents that provides automated machine enrollment with operator approval workflow.

## Overview

The MID Bootstrap Server is the operator-facing component of the MID (Machine Identity) system. It provides a web dashboard and API for managing machine enrollment requests. When an operator approves a machine, the server generates a one-time bootstrap token via Vault's MID auth plugin, which the agent then uses to obtain its certificate.

## Features

- **Web Dashboard**: Visual interface for approving/denying machine enrollment requests
- **Vault Integration**: Generates one-time bootstrap tokens via vault-secrets-mid
- **Vault Health Monitoring**: Real-time Vault health status in dashboard header
- **One-Time Tokens**: Each approval generates exactly one token; re-enrollment requires re-approval
- **Multiple Security Modes**:
  - Manual approval queue
  - Trusted network auto-approval
  - TPM attestation verification with auto-approval option
- **Flexible Authentication**: Basic auth, JWT, or combined authentication for dashboard access
- **Persistent Storage**: SQLite backend for production, in-memory for development
- **Agent Registration**: Heartbeat tracking with optional mTLS verification
- **Machine Tracking**: Tracks hostname, IPs, MACs, OS info, uptime, CA status
- **Audit Logging**: Comprehensive audit trail for all approval/denial actions
- **Request Management**: Automatic cleanup of expired requests

## Documentation

- [API Reference](docs/API.md) - Complete API endpoint documentation
- [Web Interface](docs/WEB_INTERFACE.md) - Dashboard usage guide
- [Configuration](docs/CONFIGURATION.md) - Configuration options reference
- [System Overview](docs/SYSTEM_OVERVIEW.md) - Architecture and component details

## Quick Start

### Prerequisites

- Go 1.21+
- HashiCorp Vault with vault-secrets-mid and pki-mid-auth plugins
- Vault token with permission to generate MID tokens

### Build

```bash
make build
# or
go build -o mid-bootstrap-server .
```

### Run

```bash
# With command-line flags
./mid-bootstrap-server \
  -listen :8443 \
  -tls-cert cert.pem \
  -tls-key key.pem \
  -vault-addr https://vault:8200 \
  -vault-token hvs.xxx \
  -mid-auth-mount mid \
  -mid-role vm

# Or with configuration file
./mid-bootstrap-server -config config.json

# Or with environment variables
export VAULT_ADDR=https://vault:8200
export VAULT_TOKEN=hvs.xxx
./mid-bootstrap-server
```

### Access Dashboard

Open https://localhost:8443 in your browser to access the operator dashboard.

## Enrollment Flow

```
Agent                     Bootstrap Server              Vault
  |                              |                        |
  |  POST /bootstrap/linux/machine                        |
  |  {hostname, IPs, MACs, OS...}                         |
  |----------------------------->|                        |
  |                              |                        |
  |  {"status": "pending_approval", "queue_position": 3}  |
  |<-----------------------------|                        |
  |                              |                        |
  |  ... agent polls periodically ...                     |
  |                              |                        |
  |              Operator clicks "Approve" in dashboard   |
  |                              |                        |
  |                              |  POST /v1/auth/mid/tokens/generate
  |                              |----------------------->|
  |                              |                        |
  |                              |  {token, token_id, ttl}|
  |                              |<-----------------------|
  |                              |                        |
  |  POST /bootstrap/linux/machine (next poll)            |
  |----------------------------->|                        |
  |                              |                        |
  |  {"status": "approved", "token": {...}}               |
  |<-----------------------------|                        |
  |                              |                        |
  |  POST /v1/auth/mid/login (token exchange)             |
  |------------------------------------------------------>|
  |                              |                        |
  |  {certificate, private_key, ca_chain}                 |
  |<------------------------------------------------------|
```

## API Endpoints

### Bootstrap API (for agents)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /bootstrap/{os}/machine` | POST | Submit bootstrap request |
| `POST /registration` | POST | Agent heartbeat/registration |
| `GET /health` | GET | Health check |
| `GET /version` | GET | Server version |

### Admin API (for operators)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /api/requests` | GET | List all requests |
| `GET /api/requests?status=pending` | GET | List requests by status |
| `GET /api/requests/{id}` | GET | Get specific request |
| `DELETE /api/requests/{id}` | DELETE | Remove a request |
| `POST /api/approve` | POST | Approve a request |
| `POST /api/deny` | POST | Deny a request |
| `GET /api/stats` | GET | Get dashboard statistics |
| `GET /api/systems` | GET | List registered agents |
| `GET /api/system-stats` | GET | Get system statistics |
| `GET /api/audit` | GET | Get audit log entries |
| `GET /api/vault-status` | GET | Get Vault health status |
| `POST /api/manual-bootstrap` | POST | Manual token generation |
| `GET /api/generate-token` | GET | Generate API token |

See [API Reference](docs/API.md) for detailed request/response formats.

## Agent Configuration

Configure MAG agents to use this bootstrap server:

```json
{
  "auto_bootstrap_enabled": true,
  "auto_bootstrap_server_url": "https://bootstrap.example.org:8443",
  "auto_bootstrap_interval_seconds": 30,
  "auto_bootstrap_jitter_seconds": 10,
  "auto_bootstrap_tls_skip_verify": false,
  "bootstrap_vault_addr": "https://vault:8200",
  "bootstrap_vault_auth_path": "mid",
  "bootstrap_role": "vm"
}
```

## Configuration Options

### Server & TLS Settings

| Option | Description | Default |
|--------|-------------|---------|
| `listen_addr` | Server listen address | `:8443` |
| `tls_cert` | TLS certificate path | - |
| `tls_key` | TLS private key path | - |
| `tls_min_version` | Minimum TLS version (`1.2` or `1.3`) | `1.2` |

### Vault Connection & Authentication

| Option | Description | Default |
|--------|-------------|---------|
| `vault_addr` | Vault server address | `http://127.0.0.1:8200` |
| `vault_ca_cert` | Vault CA certificate path | - |
| `vault_skip_verify` | Skip Vault TLS verification | `false` |
| `vault_namespace` | Vault namespace (Enterprise) | - |
| `vault_health_check_interval` | Health check interval (0 to disable) | `20s` |

### Bootstrap & Vault Auth

| Option | Description | Default |
|--------|-------------|---------|
| `bootstrap_type` | `certificate` (MID auth) or `token` (Vault JWT login) | `certificate` |
| `vault_jwt_source` | JWT source: `file:///`, `http://`, `https://`, or `exec:///` | - |
| `vault_auth_role` | Vault role for JWT auth | - |
| `vault_auth_mount` | JWT auth mount path | `jwt` |

### MID Auth Settings (Certificate Bootstrap Only)

| Option | Description | Default |
|--------|-------------|---------|
| `mid_auth_mount` | MID auth mount path | `mid` |
| `mid_role` | MID role for token generation | `vm` |

### Security Settings

| Option | Description | Default |
|--------|-------------|---------|
| `request_ttl` | TTL for pending requests | `24h` |
| `cleanup_interval` | Cleanup run interval | `1h` |
| `trusted_networks` | CIDRs for trusted networks | `[]` |
| `auto_approve_from_trust` | Auto-approve from trusted networks | `false` |
| `auto_approve_tpm` | Auto-approve when TPM attestation verified | `false` |
| `require_tpm` | Require TPM attestation | `false` |

### Web Dashboard & Authentication

| Option | Description | Default |
|--------|-------------|---------|
| `web_enabled` | Enable web dashboard | `true` |
| `session_secret` | Session cookie secret | `change-me-in-production` |
| `web_auth_method` | Auth method: `none`, `basic`, `jwt`, `basic+jwt`, `jwt+basic` | `none` |
| `web_auth_realm` | HTTP Basic auth realm | `MID Bootstrap Server` |
| `web_auth_users` | Map of username to credentials | `{}` |

### JWT Authentication (for web_auth_method with jwt)

| Option | Description | Default |
|--------|-------------|---------|
| `jwt_secret` | HMAC secret for HS256/HS384/HS512 | - |
| `jwt_public_key` | Path to PEM public key file | - |
| `jwt_jwks_addr` | URL to JWKS endpoint | - |
| `jwt_issuer` | Expected `iss` claim | - |
| `jwt_audience` | Expected `aud` claim | - |
| `jwt_claim_user` | JWT claim for username | `sub` |
| `jwt_claim_role` | JWT claim for roles | - |
| `jwt_default_roles` | Default roles when claim missing | `["Operator"]` |

### Storage Settings

| Option | Description | Default |
|--------|-------------|---------|
| `store_type` | Storage backend: `memory` or `sqlite` | `memory` |
| `store_path` | Path to SQLite database file | `bootstrap.db` |

### Registration mTLS Settings

| Option | Description | Default |
|--------|-------------|---------|
| `registration_require_mtls` | Require client cert for `/registration` | `false` |
| `registration_ca_cert` | CA cert for verifying client certs | - |

**Basic Auth Example:**
```json
{
  "web_auth_method": "basic",
  "web_auth_users": {
    "admin": {
      "password_hash": "<sha256-hash>",
      "roles": ["admin"]
    }
  }
}
```

Generate password hash: `echo -n 'password' | sha256sum | cut -d' ' -f1`

**JWT Auth Example:**
```json
{
  "web_auth_method": "jwt",
  "jwt_jwks_addr": "https://auth.example.org/.well-known/jwks.json",
  "jwt_issuer": "https://auth.example.org"
}
```

See [Configuration Reference](docs/CONFIGURATION.md) for complete options.

## Vault Configuration

### vault-secrets-mid Plugin

The server requires the vault-secrets-mid plugin to be enabled:

```bash
# Enable MID auth
vault auth enable -path=mid mid

# Create a role
vault write auth/mid/roles/vm \
    pki_mount=pki \
    pki_role=agent \
    allowed_domains="example.org" \
    ttl=1h \
    max_ttl=24h
```

### Policy

Create a Vault policy for the bootstrap server:

```hcl
# Allow generating bootstrap tokens
path "auth/mid/tokens/generate" {
  capabilities = ["create", "update"]
}
```

## Security Considerations

- **TLS**: Always use TLS in production (`tls_cert` and `tls_key`)
- **Vault Token**: Use a token with minimal permissions (only MID token generation)
- **Trusted Networks**: Be conservative with `trusted_networks` configuration
- **One-Time Tokens**: Tokens are delivered once and status resets to pending
- **Re-approval Required**: Agent restarts require new operator approval
- **Persistent Storage**: Use SQLite in production for audit trail and recovery
- **Authentication**: Enable `basic` or `jwt` authentication for dashboard access
- **Registration mTLS**: Consider enabling for secure agent heartbeats

## License

MIT
