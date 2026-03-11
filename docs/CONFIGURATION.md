# MID Bootstrap Server Configuration

This document provides a complete reference for configuring the MID Bootstrap Server.

## Configuration Methods

Configuration can be provided through three methods (in order of precedence):

1. **Command-line flags** (highest priority)
2. **Configuration file** (JSON)
3. **Environment variables** (for Vault settings)
4. **Default values** (lowest priority)

---

## Command-Line Flags

```bash
mid-bootstrap-server [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-config` | string | - | Path to JSON configuration file |
| `-listen` | string | `:8443` | Server listen address (host:port) |
| `-tls-cert` | string | - | Path to TLS certificate file |
| `-tls-key` | string | - | Path to TLS private key file |
| `-vault-addr` | string | - | Vault server address |
| `-vault-token` | string | - | Vault authentication token |
| `-mid-auth-mount` | string | `mid` | Vault MID auth mount path |
| `-mid-role` | string | `vm` | Vault MID role for token generation |

### Examples

```bash
# Minimal with command-line flags
mid-bootstrap-server \
  -vault-addr http://vault:8200 \
  -vault-token s.xxxxx

# With TLS enabled
mid-bootstrap-server \
  -listen :8443 \
  -tls-cert /path/to/cert.pem \
  -tls-key /path/to/key.pem \
  -vault-addr https://vault:8200 \
  -vault-token s.xxxxx

# Using a config file
mid-bootstrap-server -config /etc/mid-bootstrap/config.json
```

---

## Configuration File

The configuration file is in JSON format. All fields are optional except where noted.

### Complete Example

```json
{
  "listen_addr": ":8443",
  "tls_cert": "/etc/mid-bootstrap/server.crt",
  "tls_key": "/etc/mid-bootstrap/server.key",
  "tls_min_version": "1.2",

  "vault_addr": "https://vault.example.org:8200",
  "vault_ca_cert": "/etc/mid-bootstrap/vault-ca.pem",
  "vault_skip_verify": false,
  "vault_namespace": "",

  "bootstrap_type": "token",
  "vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
  "vault_auth_role": "vm",
  "vault_auth_mount": "jwt",

  "vault_health_check_interval": "20s",

  "request_ttl": "24h",
  "cleanup_interval": "1h",
  "default_retry_after": 300,

  "trusted_networks": ["10.0.0.0/8", "192.168.0.0/16"],
  "auto_approve_from_trust": false,
  "auto_approve_tpm": false,
  "auto_approve_dns": false,
  "require_tpm": false,

  "provisioning_windows": [
    {
      "start": "09:00",
      "end": "17:00",
      "timezone": "America/New_York",
      "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    }
  ],

  "web_enabled": true,
  "web_path_prefix": "/admin",
  "session_secret": "your-secure-secret-here",
  "web_auth_method": "basic",
  "web_auth_realm": "MID Bootstrap Server",
  "web_auth_users": {
    "admin": {
      "password_hash": "5e884898da28047d9164b9cde84bfdc3c7a8e3b5d9b2...",
      "roles": ["admin"]
    }
  },

  "store_type": "sqlite",
  "store_path": "/var/lib/mid-bootstrap/bootstrap.db",

  "registration_require_mtls": false,
  "registration_ca_cert": "",

  "alert_stale_agent_minutes": 10,
  "alert_check_interval": 60
}
```

---

## Configuration Reference

### Server Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | `:8443` | Address and port to listen on |
| `tls_cert` | string | - | Path to TLS certificate file (PEM) |
| `tls_key` | string | - | Path to TLS private key file (PEM) |
| `tls_min_version` | string | `1.2` | Minimum TLS version (`1.2` or `1.3`) |

**Notes:**
- If both `tls_cert` and `tls_key` are provided, HTTPS is enabled
- Without TLS, the server runs plain HTTP (not recommended for production)
- The listen address can include a host (e.g., `127.0.0.1:8443` for localhost only)
- Use `tls_min_version: "1.3"` for stricter security (TLS 1.3 only)

### Vault Connection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vault_addr` | string | `http://127.0.0.1:8200` | Vault server URL |
| `vault_ca_cert` | string | - | Path to CA certificate for Vault TLS |
| `vault_skip_verify` | boolean | `false` | Skip TLS verification (dev only) |
| `vault_namespace` | string | - | Vault namespace (Enterprise feature) |

### Vault Authentication & Bootstrap Mode

The server authenticates to Vault using **JWT** from an OIDC provider (e.g., Kubernetes bound service account). Static Vault tokens should be avoided as they are secrets at rest.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bootstrap_type` | string | `certificate` | Bootstrap mode: `certificate` (MID auth) or `token` (Vault JWT login) |
| `vault_jwt_source` | string | - | JWT source: `file:///`, `http://`, `https://`, or `exec:///` |
| `vault_auth_role` | string | - | Vault role name for JWT auth |
| `vault_auth_mount` | string | `jwt` | JWT auth mount path in Vault |

#### Token Bootstrap (Recommended)

The server fetches a JWT from `vault_jwt_source`, logs into Vault's JWT auth backend, and returns the resulting Vault client token to the agent. The `vault_jwt_source` is the single JWT source — it can be a file or an HTTP endpoint:

```json
{
  "bootstrap_type": "token",
  "vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
  "vault_auth_role": "vm",
  "vault_auth_mount": "jwt"
}
```

**Notes:**
- `vault_auth_role` and `vault_jwt_source` are required for token bootstrap
- The JWT is fetched on each bootstrap request
- Default mount path is `jwt` if not specified
- See [VAULT_JWT.md](VAULT_JWT.md) for full Vault setup instructions

#### Certificate Bootstrap

Uses Vault's MID auth plugin to generate one-time bootstrap tokens. Requires `mid_auth_mount` and `mid_role`.

### Vault MID Auth Settings (Certificate Bootstrap Only)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mid_auth_mount` | string | `mid` | Mount path of vault-secrets-mid |
| `mid_role` | string | `vm` | MID role for generating tokens |

**Notes:**
- Only required when `bootstrap_type` is `certificate` (the default)
- These settings must match your Vault configuration
- The role determines the certificate parameters for enrolled machines

### Vault Health Check Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vault_health_check_interval` | duration | `20s` | How often to check Vault health (0 to disable) |

**Notes:**
- The server periodically checks Vault health at `/v1/sys/health`
- Health status is displayed in the web dashboard header
- Set to `0` or `0s` to disable health checking
- Valid duration formats: `20s`, `1m`, `5m`

### Request Lifecycle

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `request_ttl` | duration | `24h` | TTL for pending requests |
| `cleanup_interval` | duration | `1h` | How often to run cleanup |
| `default_retry_after` | integer | `300` | Suggested retry delay (seconds) |

**Duration format:** `1h`, `30m`, `24h`, `7d` (Go duration syntax)

**Notes:**
- Pending requests older than `request_ttl` are marked expired and deleted
- Approved/denied requests are cleaned up after 7 days
- `default_retry_after` is sent to agents as a hint for polling interval

### Security Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trusted_networks` | []string | `[]` | CIDR blocks for trusted networks |
| `auto_approve_from_trust` | boolean | `false` | Auto-approve from trusted networks |
| `auto_approve_tpm` | boolean | `false` | Auto-approve when TPM attestation is verified |
| `auto_approve_dns` | boolean | `false` | Auto-approve when reverse DNS matches hostname |
| `require_tpm` | boolean | `false` | Require TPM attestation |

**Notes:**
- `trusted_networks` uses CIDR notation (e.g., `10.0.0.0/8`, `192.168.1.0/24`)
- Auto-approval bypasses the web dashboard for machines in trusted networks
- When `require_tpm` is true, machines without TPM attestation are rejected
- `auto_approve_tpm` allows automatic approval when TPM attestation passes verification
- `auto_approve_dns` performs a reverse DNS lookup on the client IP and auto-approves if the result matches the hostname in the bootstrap request (requires proper DNS infrastructure). Works behind load balancers via `X-Forwarded-For` and `X-Real-IP` headers.

### Provisioning Windows

| Field | Type | Description |
|-------|------|-------------|
| `provisioning_windows` | array | Time-based provisioning restrictions |
| `provisioning_windows[].start` | string | Start time (24-hour format, e.g., `09:00`) |
| `provisioning_windows[].end` | string | End time (24-hour format, e.g., `17:00`) |
| `provisioning_windows[].timezone` | string | IANA timezone (e.g., `America/New_York`) |
| `provisioning_windows[].days` | []string | Days of week (e.g., `["Monday", "Friday"]`) |

**Notes:**
- Provisioning windows are optional
- When configured, machines can only be provisioned within the specified windows
- Multiple windows can be configured (any match allows provisioning)

### Web UI Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `web_enabled` | boolean | `true` | Enable the web dashboard |
| `web_path_prefix` | string | `/admin` | URL prefix for admin UI |
| `session_secret` | string | `change-me-in-production` | Secret for session cookies |

**Notes:**
- Set `web_enabled: false` to disable the dashboard entirely
- Change `session_secret` in production to a secure random value
- The dashboard is served at the root URL (`/`) regardless of `web_path_prefix`

### Web Authentication

The admin dashboard supports multiple authentication methods to restrict access.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `web_auth_method` | string | `none` | Auth method (see options below) |
| `web_auth_realm` | string | `MID Bootstrap Server` | HTTP Basic auth realm |
| `web_auth_users` | object | `{}` | Map of username to user credentials |

**Authentication Methods:**

| Method | Description |
|--------|-------------|
| `none` | No authentication (anonymous access) |
| `basic` | HTTP Basic authentication only |
| `jwt` | JWT Bearer token authentication only |
| `basic+jwt` | Try Basic first, then JWT (first success wins) |
| `jwt+basic` | Try JWT first, then Basic (first success wins) |

#### No Authentication

By default, the dashboard has no authentication:

```json
{
  "web_auth_method": "none"
}
```

**Warning:** Only use this in development or when the dashboard is protected by other means (VPN, reverse proxy auth, etc.).

#### Basic Authentication

HTTP Basic authentication protects the admin dashboard and API:

```json
{
  "web_auth_method": "basic",
  "web_auth_realm": "MID Bootstrap Server Admin",
  "web_auth_users": {
    "admin": {
      "password_hash": "5e884898da28047d9164b9cde84bfdc3c7...",
      "roles": ["admin"]
    },
    "viewer": {
      "password_hash": "ef92b778ba8cd34...",
      "roles": ["viewer"]
    }
  }
}
```

**User Configuration:**

| Field | Type | Description |
|-------|------|-------------|
| `password_hash` | string | SHA-256 hash of the password (hex encoded, recommended) |
| `password` | string | Plaintext password (not recommended, for testing only) |
| `roles` | []string | User roles (e.g., `["admin"]`, `["viewer"]`) |

**Generate password hash:**
```bash
# Linux
echo -n 'your-password' | sha256sum | cut -d' ' -f1

# macOS
echo -n 'your-password' | shasum -a 256 | cut -d' ' -f1
```

#### JWT Authentication

JWT Bearer token authentication for programmatic access or SSO integration:

```json
{
  "web_auth_method": "jwt",
  "jwt_jwks_addr": "https://auth.example.org/.well-known/jwks.json",
  "jwt_issuer": "https://auth.example.org",
  "jwt_audience": "mid-bootstrap-server",
  "jwt_claim_user": "sub",
  "jwt_claim_role": "roles",
  "jwt_default_roles": ["Operator"]
}
```

**JWT Configuration Options:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `jwt_secret` | string | - | HMAC secret for HS256/HS384/HS512 algorithms |
| `jwt_public_key` | string | - | Path to PEM public key file for RS*/ES*/PS* algorithms |
| `jwt_jwks_addr` | string | - | URL to JWKS endpoint for dynamic key retrieval |
| `jwt_issuer` | string | - | Expected `iss` claim (optional validation) |
| `jwt_audience` | string | - | Expected `aud` claim (optional validation) |
| `jwt_claim_user` | string | `sub` | JWT claim to use for username |
| `jwt_claim_role` | string | - | JWT claim to use for roles |
| `jwt_default_roles` | []string | `["Operator"]` | Default roles when `jwt_claim_role` is not set or missing |

**Key Source (pick one):**
- `jwt_secret` - For HMAC-based tokens (HS256, HS384, HS512)
- `jwt_public_key` - For asymmetric tokens (RS256, ES256, PS256, etc.)
- `jwt_jwks_addr` - For dynamic key retrieval from JWKS endpoint

**JWT Example with HMAC:**
```json
{
  "web_auth_method": "jwt",
  "jwt_secret": "your-256-bit-secret-key-here",
  "jwt_issuer": "my-auth-server"
}
```

**JWT Example with Public Key:**
```json
{
  "web_auth_method": "jwt",
  "jwt_public_key": "/etc/mid-bootstrap/jwt-public.pem",
  "jwt_issuer": "my-auth-server"
}
```

#### Combined Authentication (Basic + JWT)

Use combined authentication to support both methods:

```json
{
  "web_auth_method": "basic+jwt",
  "web_auth_users": {
    "admin": {"password_hash": "..."}
  },
  "jwt_jwks_addr": "https://auth.example.org/.well-known/jwks.json"
}
```

**Notes:**
- `basic+jwt` tries Basic auth first, then JWT if Basic fails
- `jwt+basic` tries JWT first, then Basic if JWT fails
- Both methods must be configured when using combined auth

**Protected Endpoints:**
- All `/api/*` endpoints (list, approve, deny, stats)
- The web dashboard (`/`, `/system`, `/audit`, `/manual-bootstrap`)
- WebSocket endpoint (`/ws`)
- **Not protected:** `/bootstrap/*` endpoints (agents need unauthenticated access)
- **Not protected:** `/health`, `/version`, `/swagger/*`

### Storage Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `store_type` | string | `memory` | Storage backend: `memory` or `sqlite` |
| `store_path` | string | `bootstrap.db` | Path to SQLite database file |

**Storage Types:**

| Type | Description | Use Case |
|------|-------------|----------|
| `memory` | In-memory storage (lost on restart) | Development, testing |
| `sqlite` | Persistent SQLite database | Production |

**SQLite Example:**
```json
{
  "store_type": "sqlite",
  "store_path": "/var/lib/mid-bootstrap/bootstrap.db"
}
```

**Notes:**
- `store_path` is required when `store_type` is `sqlite`
- SQLite database is created automatically if it doesn't exist
- Memory store is useful for development but loses all data on restart
- SQLite provides persistence for bootstrap requests, agent registrations, and audit logs

### Registration mTLS Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `registration_require_mtls` | boolean | `false` | Require client certificate for `/registration` endpoint |
| `registration_ca_cert` | string | - | Path to CA cert for verifying client certificates |

**mTLS Example:**
```json
{
  "registration_require_mtls": true,
  "registration_ca_cert": "/etc/mid-bootstrap/client-ca.pem"
}
```

**Notes:**
- When enabled, agents must present a valid client certificate to register
- The `/registration` endpoint is used for agent heartbeats after bootstrap
- `registration_ca_cert` is required when `registration_require_mtls` is true
- Client certificate identity (CN or SPIFFE ID) is recorded in the registration

### Alert Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `alert_stale_agent_minutes` | integer | `10` | Minutes before an agent is considered stale |
| `alert_check_interval` | integer | `60` | Seconds between stale agent checks |

**Alert Example:**
```json
{
  "alert_stale_agent_minutes": 15,
  "alert_check_interval": 30
}
```

**Notes:**
- Stale agent alerts are created when an agent hasn't sent a heartbeat within `alert_stale_agent_minutes`
- The background checker runs every `alert_check_interval` seconds
- Stale alerts are automatically resolved when the agent sends a new heartbeat
- Version change alerts are created when an agent registers with a different version
- Alerts can be viewed and managed via the `/alerts` dashboard or `/api/alerts` API
- WebSocket subscribers receive real-time `new_alert`, `alert_acknowledged`, and `alert_resolved` events

---

## Environment Variables

The following environment variables are supported:

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | Vault server address (fallback if not in config) |
| `VAULT_TOKEN` | Vault token (fallback if not in config) |

Environment variables are only used when the corresponding config option is not set.

---

## Configuration Priority

When the same setting is specified in multiple places:

1. **Command-line flag** (wins)
2. **Config file**
3. **Environment variable**
4. **Default value**

Example:
```bash
# Config file has vault_addr: "https://vault1:8200"
# This command-line flag overrides it:
mid-bootstrap-server -config config.json -vault-addr https://vault2:8200
```

---

## Production Recommendations

### Security Checklist

1. **Enable TLS** - Always use HTTPS in production
   ```json
   {
     "tls_cert": "/path/to/cert.pem",
     "tls_key": "/path/to/key.pem",
     "tls_min_version": "1.2"
   }
   ```

2. **Use JWT authentication** - Avoid static Vault tokens (secrets at rest)
   ```json
   {
     "bootstrap_type": "token",
     "vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
     "vault_auth_role": "vm"
   }
   ```

3. **Enable web authentication** - Protect the admin dashboard
   ```json
   {
     "web_auth_method": "basic",
     "web_auth_users": {
       "admin": {"password_hash": "..."}
     }
   }
   ```

4. **Use persistent storage** - Enable SQLite for production
   ```json
   {
     "store_type": "sqlite",
     "store_path": "/var/lib/mid-bootstrap/bootstrap.db"
   }
   ```

5. **Set session secret** - Use a secure random value
   ```bash
   openssl rand -base64 32
   ```

6. **Don't skip TLS verification**
   ```json
   {
     "vault_skip_verify": false
   }
   ```

7. **Consider TPM requirement** - For high-security environments
   ```json
   {
     "require_tpm": true,
     "auto_approve_tpm": true
   }
   ```

8. **Consider DNS auto-approval** - For environments with trusted DNS infrastructure
   ```json
   {
     "auto_approve_dns": true
   }
   ```
   This performs a reverse DNS lookup on the client IP and auto-approves if the result matches the hostname. Useful when your DNS is authoritative and properly configured.

9. **Enable registration mTLS** - For secure agent heartbeats
   ```json
   {
     "registration_require_mtls": true,
     "registration_ca_cert": "/etc/mid-bootstrap/client-ca.pem"
   }
   ```

### Minimal Production Config (Token Bootstrap)

```json
{
  "listen_addr": ":8443",
  "tls_cert": "/etc/mid-bootstrap/server.crt",
  "tls_key": "/etc/mid-bootstrap/server.key",
  "tls_min_version": "1.2",

  "vault_addr": "https://vault.internal:8200",
  "vault_ca_cert": "/etc/mid-bootstrap/vault-ca.pem",
  "vault_health_check_interval": "20s",

  "bootstrap_type": "token",
  "vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
  "vault_auth_role": "vm",
  "vault_auth_mount": "jwt",

  "store_type": "sqlite",
  "store_path": "/var/lib/mid-bootstrap/bootstrap.db",

  "session_secret": "YOUR-SECURE-RANDOM-SECRET",
  "web_enabled": true,
  "web_auth_method": "basic",
  "web_auth_users": {
    "admin": {
      "password_hash": "YOUR-SHA256-HASH",
      "roles": ["admin"]
    }
  }
}
```

### Development Config

```json
{
  "listen_addr": ":8443",
  "vault_addr": "http://127.0.0.1:8200",
  "bootstrap_type": "token",
  "vault_jwt_source": "file:///tmp/dev-jwt",
  "vault_auth_role": "dev",
  "vault_auth_mount": "jwt",
  "store_type": "memory",
  "web_enabled": true,
  "web_auth_method": "none"
}
```

### JWT Authentication Config (SSO)

```json
{
  "listen_addr": ":8443",
  "tls_cert": "/etc/mid-bootstrap/server.crt",
  "tls_key": "/etc/mid-bootstrap/server.key",

  "vault_addr": "https://vault.internal:8200",

  "bootstrap_type": "token",
  "vault_jwt_source": "file:///var/run/secrets/tokens/vault-token",
  "vault_auth_role": "vm",
  "vault_auth_mount": "jwt",

  "store_type": "sqlite",
  "store_path": "/var/lib/mid-bootstrap/bootstrap.db",

  "web_enabled": true,
  "web_auth_method": "jwt",
  "jwt_jwks_addr": "https://auth.example.org/.well-known/jwks.json",
  "jwt_issuer": "https://auth.example.org",
  "jwt_audience": "mid-bootstrap-server",
  "jwt_claim_user": "email",
  "jwt_claim_role": "groups",
  "jwt_default_roles": ["Operator"]
}
```

---

## Validation

The server validates configuration at startup:

**Required fields:**
- `listen_addr`
- `vault_addr`

**Conditional requirements:**
- `vault_jwt_source` and `vault_auth_role` when `bootstrap_type` is `token`
- `mid_auth_mount` and `mid_role` when `bootstrap_type` is `certificate`
- At least one user in `web_auth_users` when `web_auth_method` includes `basic`
- One of `jwt_secret`, `jwt_public_key`, or `jwt_jwks_addr` when `web_auth_method` includes `jwt`
- `store_path` when `store_type` is `sqlite`
- `registration_ca_cert` when `registration_require_mtls` is `true`

**Validated at runtime:**
- Vault connectivity and token validity
- TLS certificate/key pair (if provided)
- Vault MID auth mount accessibility
- JWT key/JWKS endpoint accessibility (if configured)

If validation fails, the server will exit with an error message.

---

## All Configuration Options Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| **Server** ||||
| `listen_addr` | string | `:8443` | Server listen address |
| `tls_cert` | string | - | TLS certificate path |
| `tls_key` | string | - | TLS private key path |
| `tls_min_version` | string | `1.2` | Minimum TLS version |
| **Vault Connection** ||||
| `vault_addr` | string | `http://127.0.0.1:8200` | Vault server URL |
| `vault_ca_cert` | string | - | Vault CA certificate path |
| `vault_skip_verify` | boolean | `false` | Skip Vault TLS verification |
| `vault_namespace` | string | - | Vault namespace (Enterprise) |
| **Bootstrap & Vault Auth** ||||
| `bootstrap_type` | string | `certificate` | `certificate` (MID auth) or `token` (JWT login) |
| `vault_jwt_source` | string | - | JWT source: `file:///`, `http://`, `https://`, or `exec:///` |
| `vault_auth_role` | string | - | Vault role for JWT auth |
| `vault_auth_mount` | string | `jwt` | JWT auth mount path in Vault |
| **Vault MID (certificate bootstrap only)** ||||
| `mid_auth_mount` | string | `mid` | MID auth mount path |
| `mid_role` | string | `vm` | MID role name |
| **Vault Health** ||||
| `vault_health_check_interval` | duration | `20s` | Health check interval (0 to disable) |
| **Request Handling** ||||
| `request_ttl` | duration | `24h` | Pending request TTL |
| `cleanup_interval` | duration | `1h` | Cleanup run interval |
| `default_retry_after` | integer | `300` | Suggested retry delay (seconds) |
| **Security** ||||
| `trusted_networks` | []string | `[]` | Trusted network CIDRs |
| `auto_approve_from_trust` | boolean | `false` | Auto-approve trusted networks |
| `auto_approve_tpm` | boolean | `false` | Auto-approve verified TPM |
| `auto_approve_dns` | boolean | `false` | Auto-approve when reverse DNS matches |
| `require_tpm` | boolean | `false` | Require TPM attestation |
| **Provisioning** ||||
| `provisioning_windows` | array | `[]` | Time-based restrictions |
| **Web UI** ||||
| `web_enabled` | boolean | `true` | Enable web dashboard |
| `web_path_prefix` | string | `/admin` | Admin UI URL prefix |
| `session_secret` | string | `change-me-in-production` | Session cookie secret |
| **Web Authentication** ||||
| `web_auth_method` | string | `none` | Auth method |
| `web_auth_realm` | string | `MID Bootstrap Server` | Basic auth realm |
| `web_auth_users` | object | `{}` | Basic auth users |
| **JWT Authentication** ||||
| `jwt_secret` | string | - | HMAC secret |
| `jwt_public_key` | string | - | Public key file path |
| `jwt_jwks_addr` | string | - | JWKS endpoint URL |
| `jwt_issuer` | string | - | Expected issuer claim |
| `jwt_audience` | string | - | Expected audience claim |
| `jwt_claim_user` | string | `sub` | Username claim |
| `jwt_claim_role` | string | - | Role claim |
| `jwt_default_roles` | []string | `["Operator"]` | Default roles |
| **Storage** ||||
| `store_type` | string | `memory` | Storage type |
| `store_path` | string | `bootstrap.db` | SQLite database path |
| **Registration mTLS** ||||
| `registration_require_mtls` | boolean | `false` | Require client cert |
| `registration_ca_cert` | string | - | Client CA cert path |
| **Alerts** ||||
| `alert_stale_agent_minutes` | integer | `10` | Stale agent threshold (minutes) |
| `alert_check_interval` | integer | `60` | Stale check interval (seconds) |
