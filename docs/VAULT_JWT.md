# Vault JWT Bootstrap Setup

This document describes how to configure OpenBao (Vault) to support the **token bootstrap** flow, where the mid-bootstrap-simple server authenticates on behalf of agents using JWT auth and returns a Vault client token directly.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Setup Steps](#setup-steps)
  - [1. Enable JWT Auth Method](#1-enable-jwt-auth-method)
  - [2. Configure JWT Auth with Your JWT Issuer](#2-configure-jwt-auth-with-your-jwt-issuer)
  - [3. Create a Policy for Agents](#3-create-a-policy-for-agents)
  - [4. Create a Role in JWT Auth](#4-create-a-role-in-jwt-auth)
  - [5. Configure mid-bootstrap-simple](#5-configure-mid-bootstrap-simple)
  - [6. Provide a JWT Source](#6-provide-a-jwt-source)
  - [7. Verify the Setup](#7-verify-the-setup)
- [Flow Summary](#flow-summary)
- [Troubleshooting](#troubleshooting)

---

## Overview

```
Agent → mid-bootstrap-simple → reads JWT from vault_jwt_source
                              → POST /v1/auth/jwt/login {role:"vm", jwt:"eyJ..."}
                              → receives Vault client token
                              → returns token to agent

Agent stores token
Agent uses token → GET /v1/secret/data/myapp → Vault returns secret
Token expires → Agent re-enters bootstrap
```

The server authenticates to Vault using JWT from a configured source (OIDC provider, Kubernetes bound service account, or a local agent). Static Vault tokens should be avoided as they are secrets at rest.

---

## Prerequisites

- OpenBao (or Vault) server running and unsealed
- Admin access to configure auth methods and policies
- A JWT issuer (OIDC provider, Kubernetes, or custom token service)

---

## Setup Steps

### 1. Enable JWT Auth Method

```bash
bao auth enable jwt
```

This enables the JWT auth backend at the default mount path `jwt`. If you need a custom mount path, use:

```bash
bao auth enable -path=my-jwt jwt
```

### 2. Configure JWT Auth with Your JWT Issuer

The server fetches a JWT from `vault_jwt_source` and presents it to this auth method. Vault needs to trust the JWT issuer's signing keys.

**Option A — OIDC Discovery (if your JWT issuer has a `.well-known` endpoint):**

```bash
bao write auth/jwt/config \
    oidc_discovery_url="https://your-jwt-issuer.example.com"
```

**Option B — Static JWKS URL:**

```bash
bao write auth/jwt/config \
    jwks_url="https://your-jwt-issuer.example.com/.well-known/jwks.json"
```

**Option C — Static public key (simplest for testing):**

```bash
bao write auth/jwt/config \
    jwt_validation_pubkeys="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqh...your-key...
-----END PUBLIC KEY-----"
```

### 3. Create a Policy for Agents

This defines what the agent can do with the token it receives:

```bash
bao policy write agent-read - <<'EOF'
# Allow agents to read secrets
path "secret/data/*" {
  capabilities = ["read", "list"]
}

# Allow agents to check their own token info
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF
```

Adjust the `path` to match your secret engine mount and the paths agents need access to.

### 4. Create a Role in JWT Auth

This maps JWT claims to token policies and TTL:

```bash
bao write auth/jwt/role/vm \
    role_type="jwt" \
    bound_audiences="vault" \
    user_claim="sub" \
    token_policies="agent-read" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    token_type="service"
```

Key parameters:

| Parameter | Purpose |
|-----------|---------|
| `role_type` | Must be `"jwt"` (not `"oidc"`) |
| `bound_audiences` | JWT `aud` claim must match this value |
| `user_claim` | JWT claim used as the token's entity alias (usually `sub`) |
| `token_policies` | Policies attached to the resulting token |
| `token_ttl` | Token lifetime — agent re-bootstraps when this expires |
| `token_max_ttl` | Maximum renewable lifetime |
| `token_type` | `"service"` for a standard Vault token |
| `bound_claims` | (optional) Additional claim restrictions, e.g. `{"env": "prod"}` |

### 5. Configure mid-bootstrap-simple

**Using a config file (`config.json`):**

```json
{
  "bootstrap_type": "token",
  "vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
  "vault_addr": "https://openbao.example.com:8200",
  "vault_auth_role": "vm",
  "vault_auth_mount": "jwt"
}
```

The `vault_jwt_source` is the single JWT source. Supported schemes:

| Scheme | Example | Description |
|--------|---------|-------------|
| `file://` | `file:///var/run/secrets/kubernetes.io/serviceaccount/token` | Read JWT from a local file |
| `http://` | `http://localhost:3002/token` | GET JWT from an HTTP endpoint |
| `https://` | `https://metadata.internal/token` | GET JWT from an HTTPS endpoint |
| `exec://` | `exec:///opt/mid-bootstrap/jwtgen.sh` | Execute a script, capture stdout as JWT |

**Using CLI flags:**

```bash
mid-bootstrap-simple \
  -bootstrap-type token \
  -vault-jwt-source "exec:///opt/mid-bootstrap/jwtgen.sh" \
  -vault-auth-role vm
```

Configuration fields:

| Field | Description |
|-------|-------------|
| `bootstrap_type` | Set to `"token"` for JWT bootstrap flow |
| `vault_jwt_source` | JWT source: `file:///`, `http://`, `https://`, or `exec:///` |
| `vault_auth_role` | Role name created in step 4 |
| `vault_auth_mount` | JWT auth mount path in Vault (default: `"jwt"`) |

### 6. Provide a JWT Source

The JWT at `vault_jwt_source` must be signed by a key that Vault trusts (step 2) and contain the claims the role expects (step 4). The JWT is never a static secret — it is issued by an OIDC provider and rotated automatically.

Common sources:

**Kubernetes bound service account token:**

```json
"vault_jwt_source": "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
```

Kubernetes automatically rotates this token. Configure Vault's JWT auth to trust the Kubernetes OIDC issuer (step 2, Option A).

**Local OIDC provider (file):**

```json
"vault_jwt_source": "file:///var/run/tokens/bootstrap.jwt"
```

A local OIDC provider or agent writes and rotates the JWT file.

**Local agent HTTP endpoint:**

```json
"vault_jwt_source": "http://localhost:3002/token"
```

A local agent serves the JWT over HTTP. The server fetches it on each bootstrap request.

**Script execution (exec):**

```json
"vault_jwt_source": "exec:///opt/mid-bootstrap/jwtgen.sh"
```

The server executes the script and captures stdout as the JWT. Useful for experimental setups where you generate JWTs on demand. Example script:

```bash
#!/bin/bash
# jwtgen.sh - generate a JWT for Vault auth
jwtool sign \
  --key /etc/keys/private.pem \
  --claims '{"sub":"bootstrap","aud":"vault","exp":'$(($(date +%s)+300))'}'
```

The script must print the JWT to stdout and exit 0. Stderr is captured for error reporting.

### 7. Verify the Setup

Test the JWT login manually to confirm Vault is configured correctly:

```bash
# Fetch the JWT (same source as configured)
JWT=$(cat /var/run/tokens/bootstrap.jwt)

# Login to Vault with it
bao write auth/jwt/login role=vm jwt="$JWT"
```

Expected output:

```
Key                  Value
---                  -----
token                hvs.CAES...
token_accessor       abc123...
token_duration       1h
token_renewable      true
token_policies       ["agent-read", "default"]
```

Verify the token can read secrets:

```bash
AGENT_TOKEN="hvs.CAES..."
bao kv get -mount=secret myapp
```

---

## Flow Summary

```
┌─────────────┐                 ┌────────────────────┐                 ┌─────────────┐
│    Agent    │  bootstrap req  │  mid-bootstrap     │                 │   OpenBao   │
│             │ ───────────────→│  simple            │                 │   (Vault)   │
│             │                 │                    │                 │             │
│             │                 │  Cache hit?        │                 │             │
│             │                 │  YES → return      │                 │             │
│             │                 │  cached token      │                 │             │
│             │                 │                    │                 │             │
│             │                 │  NO (miss/expired):│                 │             │
│             │                 │  1. Fetch JWT from │                 │             │
│             │                 │     vault_jwt_src  │                 │             │
│             │                 │  2. POST auth/jwt/ │                 │             │
│             │                 │     login          │ ───────────────→│             │
│             │                 │  3. Cache token    │ ◄───────────────│             │
│             │                 │                    │  Vault token    │             │
│             │  Vault token    │                    │                 │             │
│             │ ◄───────────────│                    │                 │             │
│             │                 │                    │                 │             │
│             │  Read secrets   │                    │                 │             │
│             │ ─────────────────────────────────────────────────────→ │             │
│             │ ◄───────────────────────────────────────────────────── │             │
│             │  Secret data    │                    │                 │             │
└─────────────┘                 └────────────────────┘                 └─────────────┘

Token expires → Agent re-enters bootstrap loop
```

---

## Token Caching

The bootstrap server caches the Vault token obtained from JWT login. All agents bootstrapping within the same TTL window receive the same token. This minimizes Vault API calls and avoids repeated JWT logins with the same source JWT.

**Behavior:**

1. First agent request triggers a JWT login → token is cached
2. Subsequent agents receive the cached token with remaining TTL
3. When the token expires, the next request triggers a fresh JWT login
4. The bootstrap server logs cache hits and refreshes

**Implications:**

- All agents share the same Vault token and policies — this is appropriate for bootstrap since all agents need the same secret-reading permissions
- The bootstrap server logs which agent received the token, providing the audit trail
- Short `token_ttl` (e.g., 1 hour) limits blast radius if a token is compromised
- Agents re-bootstrap automatically when the token expires

### Future Alternative: Per-Agent Tokens

If per-agent audit trails at the Vault level become a requirement, an alternative approach is to have the bootstrap server mint unique child tokens:

1. Server holds its own long-lived Vault token (from JWT login, renewed periodically)
2. For each agent, server calls `auth/token/create` to issue a short-lived child token
3. Each agent gets a unique token with its own accessor

This requires additional Vault policy (`auth/token/create` capability) and is more complex, but provides:
- Per-agent token revocation
- Vault-level audit trail per agent
- Independent TTLs per agent

---

## Troubleshooting

**"permission denied" on JWT login:**
- Verify the JWT's `aud` claim matches `bound_audiences` in the role
- Verify the JWT is signed by a key Vault trusts (check `auth/jwt/config`)
- Check that the role exists: `bao read auth/jwt/role/vm`

**"role not found":**
- Confirm the role name in `vault_auth_role` matches what was created in step 4
- Confirm `vault_auth_mount` matches the mount path from step 1

**"token expired" on agent secret read:**
- The token TTL (`token_ttl` in the role) has elapsed
- Agent should re-enter bootstrap to get a fresh token
- Consider increasing `token_ttl` or implementing token renewal

**"missing JWT" from bootstrap server:**
- Verify `vault_jwt_source` points to a valid file or HTTP endpoint
- For `file://` sources, check file permissions
- For `http://` sources, verify the endpoint is reachable and returns plain JWT text