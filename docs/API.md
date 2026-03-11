# MID Bootstrap Server API Reference

This document provides a complete reference for the MID Bootstrap Server API endpoints.

## Base URL

```
https://<bootstrap-server>:8443
```

## Authentication

The API has two categories of endpoints:

1. **Agent Endpoints** - No authentication required (agents identify by hostname/MAC)
2. **Admin Endpoints** - Currently no authentication (should be protected by network policies or reverse proxy)

---

## Agent Endpoints

These endpoints are used by MAG agents for the bootstrap workflow.

### Submit Bootstrap Request

Agents call this endpoint periodically to request enrollment or poll for approval status.

```
POST /bootstrap/{os}/machine
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `os` | string | Operating system type (e.g., `linux`, `darwin`, `windows`) |

#### Request Body

```json
{
  "hostname": "web-server-01",
  "machine_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip_addresses": ["192.168.1.100", "10.0.0.50"],
  "mac_addresses": ["00:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5f"],
  "os": "linux",
  "arch": "amd64",
  "os_version": "Ubuntu 22.04.3 LTS",
  "uptime_seconds": 86400,
  "agent_version": "1.0.0",
  "tpm_attestation": {
    "quote": "<base64-encoded>",
    "signature": "<base64-encoded>",
    "pcrs": "<base64-encoded>",
    "pcr_digest": "<base64-encoded>",
    "ak_public": "<base64-encoded>",
    "nonce": "<base64-encoded>"
  }
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | Machine hostname |
| `machine_id` | string | No | Unique machine identifier (e.g., DMI UUID) |
| `ip_addresses` | array | Yes | List of non-loopback IP addresses |
| `mac_addresses` | array | No | List of non-loopback MAC addresses |
| `os` | string | Yes | Operating system (linux, darwin, windows) |
| `arch` | string | Yes | Architecture (amd64, arm64) |
| `os_version` | string | Yes | OS version string |
| `uptime_seconds` | integer | Yes | Seconds since boot |
| `agent_version` | string | No | MAG agent version |
| `tpm_attestation` | object | No | TPM attestation data (if TPM enabled) |

#### TPM Attestation Fields

| Field | Type | Description |
|-------|------|-------------|
| `quote` | bytes | TPM2B_ATTEST structure |
| `signature` | bytes | TPMT_SIGNATURE structure |
| `pcrs` | bytes | Selected PCR values |
| `pcr_digest` | bytes | Hash of PCRs |
| `ak_public` | bytes | Attestation Key public (TPMT_PUBLIC) |
| `ak_certificate` | bytes | AK certificate (if enrolled) |
| `ek_certificate` | bytes | Endorsement Key certificate |
| `ek_public` | bytes | EK public key |
| `nonce` | bytes | Server-provided nonce from previous response |

#### Response - Pending Approval

```json
{
  "status": "pending_approval",
  "message": "Awaiting operator approval",
  "nonce": "<base64-encoded>",
  "queue_position": 3,
  "retry_after_seconds": 30
}
```

#### Response - Approved

```json
{
  "status": "approved",
  "message": "Machine approved - use this token with pki-mid-auth",
  "nonce": "<base64-encoded>",
  "token": {
    "token": "hvs.CAESIJ...",
    "token_id": "tok-abc123",
    "agent_id": "web-server-01",
    "role": "vm",
    "expires_at": "2024-01-19T10:30:00Z",
    "ttl": 3600
  }
}
```

#### Response - Denied

```json
{
  "status": "denied",
  "message": "Machine not authorized for enrollment"
}
```

#### Response - TPM Required

```json
{
  "status": "tpm_required",
  "message": "TPM attestation is required for enrollment",
  "nonce": "<base64-encoded>"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Request processed (check `status` field) |
| 400 | Invalid request body |
| 403 | Machine is denied |
| 500 | Internal server error |

#### Auto-Approval Mechanisms

The bootstrap server supports several auto-approval mechanisms that can bypass manual operator approval. When enabled, these are evaluated in the following order:

| Mechanism | Config Option | Performed By | Description |
|-----------|--------------|--------------|-------------|
| Trusted Network | `auto_approve_from_trust` | `auto-trust` | Auto-approves if client IP is in `trusted_networks` CIDR list |
| TPM Attestation | `auto_approve_tpm` | `auto-tpm` | Auto-approves if TPM quote signature is verified |
| Reverse DNS | `auto_approve_dns` | `auto-dns` | Auto-approves if reverse DNS of client IP matches hostname |

**Trusted Network Auto-Approval:**
- Checks if the client IP falls within any configured `trusted_networks` CIDR
- Useful for approving machines from known internal networks
- Least secure option - only verifies network origin

**TPM Auto-Approval:**
- Requires the agent to submit TPM attestation data (quote, PCRs, AK)
- Server verifies the quote signature using the Attestation Key
- Most secure option - provides hardware-based identity verification

**Reverse DNS Auto-Approval:**
- Performs a reverse DNS lookup on the client IP address
- Compares the result with the hostname in the bootstrap request
- Supports exact match, prefix match (short name vs FQDN), and suffix match
- Requires trusted DNS infrastructure
- Works behind load balancers: uses `X-Forwarded-For` header first, then `X-Real-IP`, then falls back to remote address
- Example: Client IP `192.168.1.100` with reverse DNS `server1.example.com` will match hostname `server1` or `server1.example.com`

When auto-approved, the response message indicates the method used:
- `"Machine approved (trusted network)"`
- `"Machine approved (TPM attestation verified)"`
- `"Machine approved (reverse DNS verified)"`

The audit log records the auto-approval with `performed_by` set to `auto-trust`, `auto-tpm`, or `auto-dns`.

---

### Health Check

```
GET /health
```

#### Response

```json
{
  "status": "ok"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Server is healthy |

---

## Admin API Endpoints

These endpoints are used by operators to manage bootstrap requests.

### List Requests

List all bootstrap requests with optional status filtering.

```
GET /api/requests
```

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `pending`, `approved`, `denied`, `expired` |

#### Response

```json
[
  {
    "id": "req-abc123",
    "hostname": "web-server-01",
    "machine_id": "550e8400-e29b-41d4-a716-446655440000",
    "ip_addresses": ["192.168.1.100"],
    "mac_addresses": ["00:1a:2b:3c:4d:5e"],
    "os": "linux",
    "arch": "amd64",
    "os_version": "Ubuntu 22.04.3 LTS",
    "uptime_seconds": 86400,
    "agent_version": "1.0.0",
    "has_tpm": false,
    "status": "pending",
    "client_ip": "192.168.1.100",
    "created_at": "2024-01-18T10:00:00Z",
    "updated_at": "2024-01-18T10:05:00Z",
    "last_seen_at": "2024-01-18T10:05:00Z",
    "request_count": 5
  }
]
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique request identifier |
| `hostname` | string | Machine hostname |
| `machine_id` | string | Machine UUID |
| `ip_addresses` | array | Detected IP addresses |
| `mac_addresses` | array | Detected MAC addresses |
| `os` | string | Operating system |
| `arch` | string | Architecture |
| `os_version` | string | OS version |
| `uptime_seconds` | integer | Machine uptime |
| `agent_version` | string | Agent version |
| `has_tpm` | boolean | Whether TPM attestation was provided |
| `status` | string | Current status |
| `status_reason` | string | Reason for current status |
| `client_ip` | string | Client IP address |
| `created_at` | timestamp | First request time |
| `updated_at` | timestamp | Last update time |
| `last_seen_at` | timestamp | Last poll time |
| `request_count` | integer | Number of poll attempts |
| `approved_by` | string | Approver name (if approved) |
| `approved_at` | timestamp | Approval time (if approved) |
| `denied_by` | string | Denier name (if denied) |
| `denied_at` | timestamp | Denial time (if denied) |
| `denial_reason` | string | Denial reason (if denied) |

---

### Get Request

Get a specific bootstrap request by ID.

```
GET /api/requests/{id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Request ID |

#### Response

Returns a single request object (same format as list).

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Request found |
| 404 | Request not found |

---

### Delete Request

Remove a bootstrap request.

```
DELETE /api/requests/{id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Request ID |

#### Response

```json
{
  "status": "deleted"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Request deleted |
| 404 | Request not found |

---

### Approve Request

Approve a pending bootstrap request. This generates a one-time token via Vault.

```
POST /api/approve
```

#### Request Body

```json
{
  "request_id": "req-abc123",
  "approved_by": "admin@example.com",
  "comment": "Approved for production deployment"
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | string | Yes | Request ID to approve |
| `approved_by` | string | No | Approver identifier |
| `comment` | string | No | Approval comment |

#### Response

```json
{
  "status": "approved",
  "hostname": "web-server-01",
  "token_id": "tok-abc123",
  "expires_at": "2024-01-19T10:30:00Z"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Request approved |
| 400 | Invalid request or request not pending |
| 404 | Request not found |
| 500 | Failed to generate token |

---

### Deny Request

Deny a bootstrap request.

```
POST /api/deny
```

#### Request Body

```json
{
  "request_id": "req-abc123",
  "denied_by": "security@example.com",
  "reason": "Unknown machine - not in asset inventory"
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | string | Yes | Request ID to deny |
| `denied_by` | string | No | Denier identifier |
| `reason` | string | No | Denial reason |

#### Response

```json
{
  "status": "denied",
  "hostname": "web-server-01",
  "reason": "Unknown machine - not in asset inventory"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Request denied |
| 400 | Invalid request |
| 404 | Request not found |

---

### Get Statistics

Get dashboard statistics.

```
GET /api/stats
```

#### Response

```json
{
  "total_requests": 150,
  "pending_requests": 5,
  "approved_requests": 140,
  "denied_requests": 3,
  "expired_requests": 2
}
```

---

## Systems API Endpoints

These endpoints manage registered agent systems.

### List Registrations

Get all registered agents (paginated, deduplicated by hostname).

```
GET /api/systems
```

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `offset` | integer | `0` | Pagination offset |
| `limit` | integer | `50` | Number of results (max 500, 0 for all) |

#### Response

```json
{
  "data": [
    {
      "agent_id": "web-server-01",
      "hostname": "web-server-01",
      "ip_addresses": ["192.168.1.100", "10.0.0.50"],
      "mac_addresses": ["00:1a:2b:3c:4d:5e"],
      "os": "linux",
      "os_version": "Ubuntu 22.04.3 LTS",
      "arch": "amd64",
      "agent_version": "1.5.0",
      "uptime_seconds": 86400,
      "last_seen_at": "2024-01-18T10:00:00Z",
      "register_count": 150,
      "ca_status": {
        "ready": true,
        "remaining_ttl": "23h45m",
        "renewal_method": "pki-mid"
      }
    }
  ],
  "total": 100,
  "offset": 0,
  "limit": 50
}
```

---

### Get Registration

Get a specific agent registration by ID.

```
GET /api/systems/{id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Agent ID |

#### Response

Returns a single registration object (same format as list data items).

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Registration found |
| 404 | Registration not found |

---

### Delete Registration

Delete an agent registration. Also deletes any associated alerts.

```
DELETE /api/systems/{id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Agent ID to delete |

#### Response

```json
{
  "status": "deleted",
  "agent_id": "web-server-01-v1.4.0",
  "hostname": "web-server-01"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Registration deleted |
| 400 | Agent ID required |
| 404 | Registration not found |
| 500 | Failed to delete |

#### Example

```bash
# Delete a legacy registration
curl -X DELETE "https://bootstrap:8443/api/systems/web-server-01-v1.4.0" \
  -u admin:password

# Response: {"status":"deleted","agent_id":"web-server-01-v1.4.0","hostname":"web-server-01"}
```

---

### Get System Statistics

Get statistics about registered agents.

```
GET /api/system-stats
```

#### Response

```json
{
  "total_agents": 100,
  "active_agents": 95,
  "ca_ready_agents": 90,
  "stale_agents": 5
}
```

---

## Alerts API Endpoints

These endpoints manage alerts for stale agents and version changes.

### List Alerts

Get all alerts.

```
GET /api/alerts
```

#### Response

```json
[
  {
    "id": "alert-abc123",
    "created_at": "2024-01-18T10:00:00Z",
    "type": "stale_agent",
    "severity": "warning",
    "agent_id": "web-server-01",
    "hostname": "web-server-01",
    "agent_version": "1.5.0",
    "message": "Agent web-server-01 has not sent heartbeat for 15 minutes",
    "last_seen_at": "2024-01-18T09:45:00Z",
    "stale_duration_min": 15,
    "acknowledged": false,
    "resolved": false
  },
  {
    "id": "alert-xyz789",
    "created_at": "2024-01-18T09:30:00Z",
    "type": "version_change",
    "severity": "info",
    "agent_id": "db-server-01-1.4.0",
    "hostname": "db-server-01",
    "agent_version": "1.4.0",
    "message": "Agent db-server-01 upgraded from 1.4.0 to 1.5.0",
    "old_version": "1.4.0",
    "new_version": "1.5.0",
    "acknowledged": true,
    "acknowledged_by": "operator",
    "acknowledged_at": "2024-01-18T09:35:00Z",
    "resolved": false
  }
]
```

#### Alert Types

| Type | Description |
|------|-------------|
| `stale_agent` | Agent has not sent heartbeat within the configured threshold |
| `version_change` | Agent registered with a new version (old version tracked) |

#### Alert Severity

| Severity | Description |
|----------|-------------|
| `info` | Informational (e.g., version change) |
| `warning` | Warning (e.g., stale agent) |
| `critical` | Critical issue requiring immediate attention |

---

### Get Alert

Get a specific alert by ID.

```
GET /api/alerts/{id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Alert ID |

#### Response

Returns a single alert object (same format as list).

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Alert found |
| 404 | Alert not found |

---

### Acknowledge Alert

Mark an alert as acknowledged.

```
POST /api/alerts/{id}/acknowledge
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Alert ID |

#### Response

```json
{
  "status": "acknowledged"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Alert acknowledged |
| 404 | Alert not found |

---

### Resolve Alert

Mark an alert as resolved.

```
POST /api/alerts/{id}/resolve
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Alert ID |

#### Request Body (optional)

```json
{
  "resolution": "manually_resolved"
}
```

#### Response

```json
{
  "status": "resolved"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Alert resolved |
| 404 | Alert not found |

---

### Delete Old Version Registration

For version change alerts, delete the old agent registration.

```
POST /api/alerts/{id}/delete-agent
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Alert ID (must be a version_change alert) |

#### Response

```json
{
  "status": "agent_deleted"
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Old registration deleted |
| 404 | Alert not found |
| 500 | Failed to delete registration |

---

### Delete Alert

Delete an alert.

```
DELETE /api/alerts/{id}
```

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Alert ID |

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Alert deleted |
| 404 | Alert not found |

---

### Get Alert Statistics

Get alert statistics.

```
GET /api/alert-stats
```

#### Response

```json
{
  "total_alerts": 25,
  "unacknowledged_count": 5,
  "stale_agent_count": 3,
  "version_change_count": 22
}
```

---

## Response Status Values

The `status` field in bootstrap responses can have these values:

| Status | Description |
|--------|-------------|
| `pending_approval` | Machine is waiting for operator approval |
| `approved` | Machine is approved, token included in response |
| `denied` | Machine is denied enrollment |
| `already_enrolled` | Machine was previously enrolled |
| `tpm_required` | TPM attestation required but not provided |
| `tpm_failed` | TPM attestation verification failed |
| `error` | Server error processing request |

---

## Error Responses

Error responses follow this format:

```json
{
  "error": "error message",
  "details": "additional details (optional)"
}
```

---

## Token Lifecycle

1. **Generation**: Token is generated when operator approves a request
2. **Delivery**: Token is returned once on agent's next poll
3. **Consumption**: Token is used with pki-mid-auth to get certificate
4. **Reset**: After delivery, request status resets to pending
5. **Re-enrollment**: Agent restart requires new approval cycle

This ensures one-time token semantics and operator visibility into all enrollments.

---

## Rate Limiting

The server does not implement rate limiting. Agents should configure appropriate polling intervals:

- **Recommended**: 30-60 seconds
- **Minimum**: 10 seconds
- **Jitter**: Add random delay to prevent thundering herd

---

## Example: Complete Enrollment Flow

```bash
# 1. Agent polls (pending)
curl -X POST https://bootstrap:8443/bootstrap/linux/machine \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-01","ip_addresses":["10.0.0.5"],"os":"linux","arch":"amd64","os_version":"Ubuntu 22.04","uptime_seconds":3600}'

# Response: {"status":"pending_approval","queue_position":1}

# 2. Operator approves via dashboard or API
curl -X POST https://bootstrap:8443/api/approve \
  -H "Content-Type: application/json" \
  -d '{"request_id":"req-abc123","approved_by":"admin"}'

# Response: {"status":"approved","token_id":"tok-xyz789"}

# 3. Agent polls again (approved)
curl -X POST https://bootstrap:8443/bootstrap/linux/machine \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-01","ip_addresses":["10.0.0.5"],"os":"linux","arch":"amd64","os_version":"Ubuntu 22.04","uptime_seconds":3660}'

# Response: {"status":"approved","token":{"token":"hvs.CAE...","role":"vm"}}

# 4. Agent exchanges token for certificate (via Vault)
curl -X POST https://vault:8200/v1/auth/mid/login \
  -H "Content-Type: application/json" \
  -d '{"token":"hvs.CAE...","hostname":"web-01"}'

# Response: {certificate, private_key, ca_chain}
```

---

## WebSocket Interface

The bootstrap server provides a WebSocket endpoint for real-time event notifications. This allows third-party systems to subscribe to events without polling.

### Connecting

```
ws://<bootstrap-server>:8443/ws
wss://<bootstrap-server>:8443/ws  # With TLS
```

**Note:** The WebSocket endpoint is protected by the same authentication as the admin API. Include credentials in the connection request.

### Message Format

All messages are JSON-encoded with this structure:

```json
{
  "type": "event_type",
  "timestamp": "2024-01-18T10:00:00Z",
  "data": { ... }
}
```

### Event Types

| Event | Description |
|-------|-------------|
| `initial_state` | Sent immediately on connection with current stats |
| `new_request` | New bootstrap request received |
| `request_approved` | Bootstrap request approved |
| `request_denied` | Bootstrap request denied |
| `request_deleted` | Bootstrap request deleted |
| `token_generated` | Bootstrap token generated |
| `agent_registered` | Agent sent registration/heartbeat |
| `pow_verified` | PoW verification passed |
| `pow_warning` | PoW verification has warnings |
| `pow_failed` | PoW verification failed |
| `new_alert` | New alert created (stale agent, version change) |
| `alert_acknowledged` | Alert acknowledged by operator |
| `alert_resolved` | Alert resolved |

### Event Data Examples

#### initial_state

```json
{
  "type": "initial_state",
  "stats": {
    "total_requests": 150,
    "pending_requests": 5,
    "approved_requests": 140,
    "denied_requests": 3,
    "expired_requests": 2
  }
}
```

#### new_request

```json
{
  "type": "new_request",
  "timestamp": "2024-01-18T10:00:00Z",
  "data": {
    "request_id": "req-abc123",
    "hostname": "web-server-01",
    "client_ip": "192.168.1.100",
    "os": "linux",
    "arch": "amd64"
  }
}
```

#### agent_registered

```json
{
  "type": "agent_registered",
  "timestamp": "2024-01-18T10:00:00Z",
  "data": {
    "agent_id": "web-server-01",
    "hostname": "web-server-01",
    "client_ip": "192.168.1.100",
    "os": "linux",
    "arch": "amd64",
    "is_new": false
  }
}
```

#### new_alert

```json
{
  "type": "new_alert",
  "timestamp": "2024-01-18T10:00:00Z",
  "data": {
    "alert_id": "alert-abc123",
    "type": "stale_agent",
    "severity": "warning",
    "hostname": "web-server-01",
    "agent_id": "web-server-01",
    "agent_version": "1.5.0",
    "message": "Agent web-server-01 has not sent heartbeat for 15 minutes"
  }
}
```

#### pow_verified

```json
{
  "type": "pow_verified",
  "timestamp": "2024-01-18T10:00:00Z",
  "data": {
    "agent_id": "web-server-01",
    "hostname": "web-server-01",
    "client_ip": "192.168.1.100",
    "status": "ok",
    "chain_valid": true,
    "work_valid": true,
    "metrics_valid": true,
    "witness_count": 3,
    "witness_threshold": 2,
    "sequence": 42
  }
}
```

### Connection Lifecycle

1. Client connects to `/ws`
2. Server sends `initial_state` with current dashboard stats
3. Server sends events as they occur
4. Server sends ping frames every 30 seconds
5. Client should respond with pong (automatic in most libraries)
6. Connection times out after 60 seconds without activity

### Using with curl

While curl doesn't support WebSocket natively, you can use `websocat` for command-line WebSocket access:

```bash
# Install websocat (various methods)
# macOS: brew install websocat
# Linux: cargo install websocat

# Connect without auth
websocat ws://localhost:8443/ws

# Connect with Basic auth
websocat -H "Authorization: Basic $(echo -n 'admin:password' | base64)" \
  ws://localhost:8443/ws

# Connect with TLS (skip verification for self-signed)
websocat --insecure wss://localhost:8443/ws

# Pretty-print JSON output
websocat ws://localhost:8443/ws | jq .
```

### Using with Python

```python
import asyncio
import websockets
import json
import base64

async def listen():
    # Basic auth header
    credentials = base64.b64encode(b"admin:password").decode()
    headers = {"Authorization": f"Basic {credentials}"}

    async with websockets.connect(
        "wss://bootstrap:8443/ws",
        extra_headers=headers
    ) as ws:
        async for message in ws:
            event = json.loads(message)
            print(f"Event: {event['type']}")
            if event['type'] == 'new_alert':
                print(f"  Alert: {event['data']['message']}")

asyncio.run(listen())
```

### Using with JavaScript/Node.js

```javascript
const WebSocket = require('ws');

// Basic auth
const credentials = Buffer.from('admin:password').toString('base64');

const ws = new WebSocket('wss://bootstrap:8443/ws', {
  headers: { 'Authorization': `Basic ${credentials}` },
  rejectUnauthorized: false  // For self-signed certs
});

ws.on('open', () => console.log('Connected'));

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log(`Event: ${event.type}`, event.data);

  // Handle specific events
  if (event.type === 'new_alert') {
    console.log(`Alert: ${event.data.message}`);
    // Send to alerting system, Slack, PagerDuty, etc.
  }
});

ws.on('close', () => {
  console.log('Disconnected, reconnecting...');
  setTimeout(connect, 5000);
});
```

### Using with Go

```go
package main

import (
    "encoding/base64"
    "encoding/json"
    "log"
    "net/http"

    "github.com/gorilla/websocket"
)

func main() {
    // Basic auth header
    auth := base64.StdEncoding.EncodeToString([]byte("admin:password"))
    header := http.Header{"Authorization": []string{"Basic " + auth}}

    conn, _, err := websocket.DefaultDialer.Dial(
        "wss://bootstrap:8443/ws",
        header,
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    for {
        _, message, err := conn.ReadMessage()
        if err != nil {
            log.Println("Read error:", err)
            return
        }

        var event map[string]interface{}
        json.Unmarshal(message, &event)
        log.Printf("Event: %s", event["type"])
    }
}
```

### Integration Examples

#### Forward Alerts to Slack

```python
import asyncio
import websockets
import json
import requests

SLACK_WEBHOOK = "https://hooks.slack.com/services/..."

async def alert_to_slack():
    async with websockets.connect("wss://bootstrap:8443/ws") as ws:
        async for message in ws:
            event = json.loads(message)
            if event['type'] == 'new_alert':
                alert = event['data']
                requests.post(SLACK_WEBHOOK, json={
                    "text": f":warning: *{alert['type']}*: {alert['message']}"
                })

asyncio.run(alert_to_slack())
```

#### Monitor Agent Health

```python
import asyncio
import websockets
import json

async def monitor_health():
    async with websockets.connect("wss://bootstrap:8443/ws") as ws:
        async for message in ws:
            event = json.loads(message)

            if event['type'] == 'agent_registered':
                print(f"Heartbeat from {event['data']['hostname']}")

            elif event['type'] == 'new_alert':
                alert = event['data']
                if alert['type'] == 'stale_agent':
                    print(f"STALE: {alert['hostname']} - {alert['message']}")

            elif event['type'] == 'pow_failed':
                print(f"POW FAILED: {event['data']['hostname']} - possible spoofing!")

asyncio.run(monitor_health())
```
