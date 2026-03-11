# Auto-DNS Hardening Options

## Problem Statement

The `auto_approve_dns` feature performs a reverse DNS lookup on the client IP and auto-approves bootstrap requests when the result matches the hostname. While this provides a level of assurance that the request originates from the correct machine, it has a critical weakness:

**Any process on the machine can fake a bootstrap request.**

Since the DNS verification only proves the request comes from an IP that resolves to the hostname, any unprivileged user or process on that machine could:
1. Submit a bootstrap request with the correct hostname
2. Pass the DNS verification
3. Receive the bootstrap token and CA credentials

This undermines the security model where only the legitimate MID agent should receive credentials.

## Load Balancer Support

The auto-DNS feature works behind load balancers and reverse proxies. The server determines the client IP using the following priority:

1. `X-Forwarded-For` header (first IP in the chain)
2. `X-Real-IP` header
3. Direct remote address (fallback)

**Load Balancer Configuration:**

Ensure your load balancer forwards the original client IP:

```nginx
# Nginx example
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

```
# HAProxy example
option forwardfor
```

**Security Note:** When using `X-Forwarded-For`, ensure your load balancer is configured to strip or replace any client-provided `X-Forwarded-For` headers to prevent IP spoofing. The bootstrap server trusts these headers, so they must come from a trusted proxy.

## Threat Model

| Threat | Description | Risk Level |
|--------|-------------|------------|
| Malicious user on host | Local user runs fake agent to steal credentials | High |
| Compromised process | Malware on host intercepts or races the real agent | High |
| Container escape | Container process requests credentials for host | Medium |
| Shared hosting | Co-tenant requests credentials for another VM | Low (if DNS properly isolated) |

## Hardening Options

### Option 1: Privileged Source Port

**Concept:** Require the agent to make requests FROM a source port < 1024. Only root can bind to privileged ports on Unix systems.

**Implementation:**
```go
// Server-side check
func isPrivilegedSourcePort(r *http.Request) bool {
    _, portStr, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return false
    }
    port, err := strconv.Atoi(portStr)
    if err != nil {
        return false
    }
    return port > 0 && port < 1024
}
```

**Agent-side:**
```go
// Bind to privileged source port
dialer := &net.Dialer{
    LocalAddr: &net.TCPAddr{Port: 600}, // Privileged port
}
transport := &http.Transport{
    DialContext: dialer.DialContext,
}
client := &http.Client{Transport: transport}
```

**Pros:**
- Simple to implement
- No additional network flows
- Proves root/CAP_NET_BIND_SERVICE capability

**Cons:**
- NAT may rewrite source ports
- Load balancers typically don't preserve source ports
- X-Forwarded-For header doesn't include port
- Only works for direct connections

**Best for:** Direct agent-to-server connections without NAT/proxies.

---

### Option 2: Privileged Port Callback

**Concept:** Agent specifies a callback port < 1024 in the request. Server connects back to deliver the token, proving the agent can bind to privileged ports.

**Protocol Flow:**
```
1. Agent -> Server: POST /bootstrap/linux/machine
   Body: { "hostname": "server1", "callback_port": 443, ... }

2. Server verifies:
   - Reverse DNS matches hostname
   - callback_port < 1024

3. Server -> Agent: POST https://<client-ip>:<callback_port>/token
   Body: { "token": "hvs.xxx", ... }

4. Agent receives token on privileged port
```

**Implementation Considerations:**
- Agent must run HTTPS server on callback port
- Server needs outbound connectivity to agents
- Firewall rules must allow server -> agent connections
- TLS verification on callback (agent presents ephemeral cert?)

**Pros:**
- Works through NAT (server connects to agent's public IP)
- Definitively proves privileged port binding
- Token never sent over agent-initiated connection

**Cons:**
- Requires server outbound connectivity
- Firewall complexity (server must reach agents)
- Additional TLS handshake for callback
- More complex implementation

**Best for:** Environments where server can reach agents, NAT is present.

---

### Option 3: Challenge-Response with Protected File

**Concept:** Server issues a challenge that agent must write to a root-protected location, then server verifies via out-of-band channel.

**Protocol Flow:**
```
1. Agent -> Server: POST /bootstrap/linux/machine
   Response: { "status": "challenge", "challenge": "abc123", "verify_path": "/root/.mid-challenge" }

2. Agent writes challenge to /root/.mid-challenge (requires root)

3. Server verifies via:
   - SSH to host and read file
   - Or agent-initiated verification endpoint with file hash

4. Server -> Agent: Token delivered after verification
```

**Pros:**
- Proves root filesystem access
- Works regardless of network topology

**Cons:**
- Requires out-of-band verification (SSH access or trust agent's hash)
- Adds latency (multi-step protocol)
- SSH key management complexity
- File must be cleaned up after

**Best for:** High-security environments with existing SSH infrastructure.

---

### Option 4: Combine DNS + TPM

**Concept:** Require BOTH reverse DNS match AND TPM attestation for auto-approval.

**Configuration:**
```json
{
  "auto_approve_dns": true,
  "auto_approve_tpm": true,
  "require_dns_and_tpm": true
}
```

**Verification:**
- Reverse DNS must match hostname
- TPM quote signature must be valid
- Both conditions required (not either/or)

**Pros:**
- Hardware-rooted trust (TPM)
- Network location verification (DNS)
- Defense in depth

**Cons:**
- Requires TPM hardware
- Not all VMs/containers have vTPM
- Excludes non-TPM machines from auto-approval

**Best for:** Environments with universal TPM availability.

---

### Option 5: Pre-Provisioned Machine Key

**Concept:** During machine provisioning, deploy a signing key to a root-protected location. Agent signs requests with this key.

**Setup (during VM provisioning):**
```bash
# Generate machine-specific key
openssl genrsa -out /etc/mid/machine-key.pem 2048
chmod 600 /etc/mid/machine-key.pem

# Register public key with bootstrap server
curl -X POST https://bootstrap:8443/api/machine-keys \
  -d '{"hostname": "server1", "public_key": "..."}'
```

**Request signing:**
```
POST /bootstrap/linux/machine
X-Machine-Signature: <base64-signature>
X-Machine-Key-ID: <key-fingerprint>

Body: { "hostname": "server1", ... }
```

**Pros:**
- Cryptographic proof of machine identity
- Works on any hardware
- Key rotation possible

**Cons:**
- Chicken-and-egg: requires initial provisioning
- Key distribution complexity
- Key compromise requires re-provisioning

**Best for:** Environments with automated VM provisioning (Terraform, Ansible, etc.)

---

### Option 6: Kernel Keyring Attestation (Linux)

**Concept:** Store a secret in the Linux kernel keyring with restricted access. Only processes with correct UID can retrieve it.

**Setup:**
```bash
# Add secret to kernel keyring (root only)
keyctl add user mid-secret "random-secret-value" @u
keyctl setperm <key-id> 0x3f000000  # Owner read only
```

**Agent retrieval:**
```go
// Only works if running as the key owner (root)
secret, err := keyctl.Read("mid-secret")
```

**Request includes:**
```json
{
  "hostname": "server1",
  "keyring_proof": "<HMAC of request using keyring secret>"
}
```

**Pros:**
- No files on disk
- Kernel-enforced access control
- Survives process restart (until reboot)

**Cons:**
- Linux-specific
- Secret lost on reboot (needs re-provisioning)
- Requires keyring setup during provisioning

**Best for:** Linux-only environments with ephemeral credentials.

---

### Option 7: Process Attestation via procfs

**Concept:** Server connects back to agent and queries the process's UID via /proc filesystem.

**Protocol Flow:**
```
1. Agent -> Server: POST /bootstrap/linux/machine
   Body: { "hostname": "server1", "callback_port": 8443, "pid": 1234 }

2. Server -> Agent: GET https://<client-ip>:8443/attest
   Response: { "pid": 1234 }

3. Server -> Host (via SSH): cat /proc/1234/status | grep Uid
   Verify: Uid: 0 0 0 0 (all root)

4. Server -> Agent: POST https://<client-ip>:8443/token
```

**Pros:**
- Direct UID verification
- Hard to fake (kernel-provided data)

**Cons:**
- Requires SSH access to hosts
- Complex multi-step protocol
- SSH key management
- Race condition between PID check and token delivery

**Best for:** High-security environments with SSH infrastructure and real-time verification needs.

---

### Option 8: Capability-Based Proof

**Concept:** Instead of requiring root, require a specific Linux capability (CAP_NET_BIND_SERVICE) that's been granted to the agent binary.

**Setup:**
```bash
# Grant capability to agent binary
setcap cap_net_bind_service=+ep /usr/local/bin/mid-agent
```

**Verification:** Same as Option 1 (privileged source port), but allows non-root execution.

**Pros:**
- Principle of least privilege (not full root)
- Still proves administrative setup
- Works with systemd service hardening

**Cons:**
- Same NAT/proxy limitations as Option 1
- Capability must be re-applied after binary updates

**Best for:** Security-conscious environments following least-privilege principles.

---

## Comparison Matrix

| Option | Root Required | Works Through NAT | Implementation Complexity | Security Level |
|--------|--------------|-------------------|--------------------------|----------------|
| 1. Privileged Source Port | Yes* | No | Low | Medium |
| 2. Privileged Port Callback | Yes* | Yes | High | High |
| 3. Challenge File | Yes | Yes | Medium | High |
| 4. DNS + TPM | No | Yes | Low | Highest |
| 5. Pre-Provisioned Key | No | Yes | Medium | High |
| 6. Kernel Keyring | Yes | Yes | Medium | High |
| 7. procfs Attestation | Yes | Yes | High | Highest |
| 8. Capability-Based | No** | No | Low | Medium |

\* Or CAP_NET_BIND_SERVICE capability
\** Requires CAP_NET_BIND_SERVICE

## Recommendations

### For Most Environments

**Recommended: Option 1 (Privileged Source Port)** combined with DNS verification.

- Simple to implement
- Minimal infrastructure changes
- Proves the agent has elevated privileges
- Suitable when agents connect directly to bootstrap server

### For NAT/Cloud Environments

**Recommended: Option 2 (Privileged Port Callback)** or **Option 5 (Pre-Provisioned Key)**.

- Option 2 if server can reach agents
- Option 5 if you have automated provisioning

### For Maximum Security

**Recommended: Option 4 (DNS + TPM)** where TPM is available.

- Hardware-rooted attestation
- Defense in depth with DNS verification
- No privileged port requirements

### For Hybrid Environments

Consider implementing multiple options and allowing per-machine configuration:

```json
{
  "auto_approve_dns": true,
  "dns_hardening_methods": ["privileged_source_port", "tpm"],
  "dns_hardening_require_any": true
}
```

## Implementation Priority

1. **Phase 1:** Privileged Source Port (Option 1) - Quick win, simple implementation
2. **Phase 2:** Privileged Port Callback (Option 2) - For NAT environments
3. **Phase 3:** DNS + TPM combination (Option 4) - For high-security needs

## References

- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Privileged Ports](https://www.w3.org/Daemon/User/Installation/PrivilegedPorts.html)
- [TPM 2.0 Attestation](https://trustedcomputinggroup.org/resource/tpm-2-0-a-brief-introduction/)
- [Kernel Keyring](https://man7.org/linux/man-pages/man7/keyrings.7.html)
