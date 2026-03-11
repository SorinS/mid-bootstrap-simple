# MID Bootstrap Server Web Interface

This document describes the web-based dashboard for managing machine bootstrap requests.

## Accessing the Dashboard

The web dashboard is served at the root URL of the bootstrap server:

```
https://<bootstrap-server>:8443/
```

## Navigation

The dashboard has five main pages accessible via the navigation bar:

| Page | URL | Description |
|------|-----|-------------|
| **Bootstrap Requests** | `/` | Main dashboard for bootstrap request management |
| **Registered Agents** | `/system` | View all registered agents and their status |
| **Alerts** | `/alerts` | Monitor stale agents and version changes |
| **Manual Bootstrap** | `/manual-bootstrap` | Generate tokens for air-gapped machines |
| **Audit Log** | `/audit` | View all approval/denial events |

---

## Bootstrap Requests Dashboard

The main dashboard provides a real-time view of all machine enrollment requests, organized into three sections:

1. **Pending Requests** - Machines waiting for operator approval
2. **Recently Approved** - Machines that have been approved
3. **Denied** - Machines that have been rejected

### Statistics Cards

At the top of the dashboard, four statistics cards display:

| Card | Color | Description |
|------|-------|-------------|
| Total Requests | Blue | All requests ever received |
| Pending | Orange | Requests awaiting approval |
| Approved | Green | Successfully approved requests |
| Denied | Red | Rejected requests |

---

## Pending Requests Section

This is the primary working area for operators. Each pending request shows:

### Machine Information

| Column | Description |
|--------|-------------|
| **Hostname** | Machine hostname (with client IP below) |
| **OS / Arch** | Operating system and architecture (with version below) |
| **IP Addresses** | All detected non-loopback IP addresses |
| **Uptime** | Hours since machine boot |
| **TPM** | Blue badge if TPM attestation was provided |
| **First Seen** | When the machine first requested enrollment |
| **Requests** | Number of poll attempts made |
| **Actions** | Approve / Deny buttons |

### Approve Action

1. Click the green **Approve** button
2. Confirm the action in the dialog
3. A bootstrap token is generated via Vault
4. Success message shows the token expiration time
5. The page refreshes automatically

The machine will receive the token on its next poll and exchange it for a certificate.

### Deny Action

1. Click the red **Deny** button
2. Enter a reason for denial in the prompt
3. The machine is marked as denied
4. The page refreshes automatically

Denied machines will receive a 403 response with the denial reason.

---

## Recently Approved Section

Shows machines that have been approved. Information displayed:

| Column | Description |
|--------|-------------|
| **Hostname** | Machine hostname |
| **Token ID** | Unique identifier for the issued token |
| **Expires** | Token expiration time |
| **Approved By** | Operator who approved the request |
| **Approved At** | When approval was granted |
| **Actions** | Remove button |

### Remove Action

Click the **Remove** button to delete the request from the dashboard. This does not revoke the issued token.

**Note:** After token delivery, requests automatically reset to "pending" status to enforce re-approval on subsequent enrollments.

---

## Denied Section

Shows machines that have been denied enrollment:

| Column | Description |
|--------|-------------|
| **Hostname** | Machine hostname |
| **Reason** | Denial reason provided by operator |
| **Denied By** | Operator who denied the request |
| **Denied At** | When denial was recorded |
| **Actions** | Remove button |

### Remove Action

Click the **Remove** button to delete the denial record. The machine can attempt enrollment again.

---

---

## Alerts Dashboard

The Alerts page (`/alerts`) monitors agent health and tracks version changes.

### Statistics Cards

| Card | Color | Description |
|------|-------|-------------|
| Total Alerts | Blue | All alerts (active and resolved) |
| Unacknowledged | Orange | Alerts awaiting operator acknowledgment |
| Stale Agents | Orange | Agents that stopped heartbeating |
| Version Changes | Blue | Agents that upgraded/changed version |

### Alert Types

#### Stale Agent Alerts

Created when an agent hasn't sent a heartbeat within the configured threshold (default: 10 minutes).

| Column | Description |
|--------|-------------|
| **Type** | `stale_agent` badge |
| **Severity** | `warning` |
| **Hostname** | Agent hostname and version |
| **Message** | Details about how long since last heartbeat |
| **Created** | When the alert was created |
| **Status** | Pending, Acknowledged, or Resolved |
| **Actions** | Ack, Resolve buttons |

**Auto-Resolution:** Stale agent alerts are automatically resolved when the agent sends a new heartbeat.

#### Version Change Alerts

Created when an agent registers with a new version, tracking the old version.

| Column | Description |
|--------|-------------|
| **Type** | `version_change` badge |
| **Severity** | `info` |
| **Hostname** | Agent hostname and old version |
| **Message** | Shows old → new version transition |
| **Created** | When the version change was detected |
| **Status** | Pending, Acknowledged, or Resolved |
| **Actions** | Ack, Resolve, Delete Old buttons |

**Delete Old:** Removes the old version's registration from the system.

### Filtering

Use the filter dropdowns to narrow the alert list:

- **Type Filter:** All Types, Stale Agents, Version Changes
- **Status Filter:** All Status, Unacknowledged, Acknowledged, Resolved

### Actions

| Button | Description |
|--------|-------------|
| **Ack** | Acknowledge the alert (marks as seen by operator) |
| **Resolve** | Mark the alert as resolved |
| **Delete Old** | (Version change only) Delete the old version registration |

### Real-Time Updates

The Alerts page connects to the WebSocket endpoint and automatically refreshes when:
- New alerts are created
- Alerts are acknowledged
- Alerts are resolved

---

## Features

### Auto-Refresh

The dashboard automatically refreshes every **30 seconds** to show new requests and status changes.

### Manual Refresh

Click the blue **Refresh** button in the "Pending Requests" header to immediately reload the page.

### Responsive Layout

The dashboard uses a responsive grid layout that adapts to different screen sizes.

### Color Coding

- **Orange/Yellow** - Pending items requiring attention
- **Green** - Approved/successful items
- **Red** - Denied/error items
- **Blue** - TPM attestation present, informational items

---

## Workflow

### Typical Operator Workflow

1. Open dashboard at `https://bootstrap-server:8443/`
2. Review pending requests in the first table
3. Verify machine details:
   - Hostname matches expected naming convention
   - IP addresses are in expected network ranges
   - OS and architecture are appropriate
   - TPM attestation present (if required)
4. Click **Approve** for legitimate machines
5. Click **Deny** with reason for unknown machines

### Security Considerations

- All approval/denial actions are logged server-side
- Each approval generates a one-time token
- Token is delivered only once, then status resets
- Re-enrollment after restart requires new approval

### Auto-Approval

When configured, machines may be automatically approved without appearing in the pending queue:

| Config Option | Method | Audit Entry |
|--------------|--------|-------------|
| `auto_approve_from_trust` | Trusted network CIDR match | `auto-trust` |
| `auto_approve_tpm` | TPM attestation verified | `auto-tpm` |
| `auto_approve_dns` | Reverse DNS matches hostname | `auto-dns` |

Auto-approved requests still appear in the audit log with the corresponding `performed_by` value. See [CONFIGURATION.md](./CONFIGURATION.md) for setup details.

---

## API-Based Management

For automation or programmatic access, use the [API endpoints](./API.md) instead of the web interface:

```bash
# List pending requests
curl https://bootstrap:8443/api/requests?status=pending

# Approve a request
curl -X POST https://bootstrap:8443/api/approve \
  -H "Content-Type: application/json" \
  -d '{"request_id": "req-abc123", "approved_by": "automation"}'

# Deny a request
curl -X POST https://bootstrap:8443/api/deny \
  -H "Content-Type: application/json" \
  -d '{"request_id": "req-xyz789", "reason": "Not in inventory"}'
```

---

## Troubleshooting

### Dashboard Not Loading

1. Verify the server is running: `curl https://bootstrap:8443/health`
2. Check TLS certificate paths if using HTTPS
3. Verify network connectivity to the server port

### Approve Button Fails

1. Check server logs for Vault connection errors
2. Verify Vault token has permission to generate MID tokens
3. Ensure the MID auth mount and role are configured correctly

### No Machines Appearing

1. Verify agents are configured with the correct bootstrap server URL
2. Check agent logs for connection errors
3. Verify TLS settings match between agent and server

### Machines Stuck in Pending

1. Approve the machine via the dashboard
2. Wait for the agent's next poll (configured interval + jitter)
3. Check agent logs for token receipt and Vault login

---

## Browser Compatibility

The dashboard is tested with modern browsers:

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

JavaScript must be enabled for approve/deny actions to work.
