# Proof of Work (PoW) Anti-Spoofing System

## Overview

The MID Agent (MAG) implements a hybrid Proof of Work system designed to prevent identity spoofing and ensure agents are who they claim to be. The system combines multiple verification layers:

1. **Heartbeat Chains** - Merkle-based proof of continuous operation
2. **Subnet Witness Protocol** - Agents vouching for each other's presence
3. **Hardware Binding** - TPM quotes, system metrics
4. **CPU-bound Proof of Work** - Prevents mass spoofing attacks

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SecureHeartbeat                                 │
├─────────────────────────────────────────────────────────────────────────┤
│  Identity          │  Proof Chain       │  Hardware Binding             │
│  - AgentID         │  - Sequence        │  - SystemMetrics              │
│  - Hostname        │  - PreviousHash    │  - TPMQuote                   │
│  - Timestamp       │  - MerkleRoot      │                               │
├─────────────────────────────────────────────────────────────────────────┤
│  Proof of Work                          │  Witnesses                    │
│  - Nonce                                │  - WitnessStatements[]        │
│  - Difficulty                           │    (from subnet neighbors)    │
│  - WorkHash                             │                               │
├─────────────────────────────────────────────────────────────────────────┤
│                            Ed25519 Signature                            │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Heartbeat Chain

Each heartbeat links to the previous one, creating a tamper-evident chain:

```go
type SecureHeartbeat struct {
    Sequence     uint64   // Monotonic counter
    PreviousHash []byte   // Hash of previous heartbeat
    MerkleRoot   []byte   // Root of all previous heartbeats
}
```

**Benefits:**
- Detects gaps in heartbeat history
- Prevents replay of old heartbeats
- Creates verifiable continuity of operation

### 2. Proof of Work

Each heartbeat requires CPU work to generate:

```go
Nonce      uint64  // Found via trial and error
Difficulty uint8   // Required leading zero bits (default: 16)
WorkHash   []byte  // SHA256(heartbeat || nonce) with N leading zeros
```

**Difficulty Levels:**

| Difficulty | Avg. Attempts | Time (~1M hash/s) |
|------------|---------------|-------------------|
| 8 | 256 | ~0.25ms |
| 16 | 65,536 | ~65ms |
| 20 | 1,048,576 | ~1s |
| 24 | 16,777,216 | ~17s |

Default difficulty is 16 bits, requiring ~65,000 hash attempts per heartbeat.

### 3. Hardware Binding

System metrics create a hardware fingerprint:

```go
type SystemMetrics struct {
    BootID        string   // Unique per boot (/proc/sys/kernel/random/boot_id)
    BootTime      int64    // System boot timestamp
    UptimeSeconds int64    // Current uptime
    MACAddresses  []string // Network interface MACs
    DiskSerial    string   // Primary disk serial
    MachineID     string   // /etc/machine-id
    ProductUUID   string   // DMI product UUID
}
```

**Verification:**
- Boot ID should remain constant between heartbeats
- Uptime should increase monotonically
- Hardware identifiers should be consistent

### 4. Subnet Witnesses

Neighboring agents attest to each other's presence:

```go
type WitnessStatement struct {
    WitnessID   string  // Agent ID of the witness
    WitnessAddr string  // IP:port of witness
    SubjectID   string  // Agent being witnessed
    Timestamp   int64   // When witnessed
    Nonce       []byte  // Challenge nonce
    Signature   []byte  // Ed25519 signature
}
```

**Protocol:**
1. Agent A sends `WitnessRequest` to neighbor Agent B
2. Agent B verifies A is reachable at claimed address
3. Agent B signs a `WitnessStatement` for A
4. A includes statement in next heartbeat

---

## Neighbor Discovery

### Current: mDNS (Multicast DNS)

The current implementation uses mDNS for discovering neighbors:

```go
// Configuration
MDNSEnabled  bool   // Enable mDNS discovery
MDNSService  string // "_mag-agent._tcp"
MDNSDomain   string // "local."
MDNSIPv4Only bool   // IPv4-only mode
```

**How it works:**
1. Agent advertises itself via mDNS service record
2. Periodically queries for other `_mag-agent._tcp` services
3. Maintains list of discovered neighbors
4. Requests witness statements from reachable neighbors

**Limitations:**
- **Link-local only**: mDNS uses multicast (224.0.0.251) which doesn't cross routers
- **Same L2 segment**: Only discovers agents on the same broadcast domain
- **Scalability**: Can cause multicast storms with many agents
- **No cross-subnet**: Agents in 10.1.x.x won't see agents in 10.2.x.x

**Best for:**
- Small deployments (< 50 agents per subnet)
- Single-subnet environments
- Edge/IoT deployments

---

## Alternative Discovery Mechanisms

### Option 1: Gossip Protocol (Recommended for Cross-Subnet)

Gossip protocols spread information by having nodes periodically exchange data with random peers. Information propagates exponentially through the network.

#### SWIM Protocol

The [SWIM (Scalable Weakly-consistent Infection-style Process Group Membership) Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf) is the foundation for modern gossip-based membership systems.

**Key characteristics:**
- O(log N) convergence time
- Constant network load per node (doesn't grow with cluster size)
- Failure detection via ping/ping-req protocol
- Information piggybacked on protocol messages

**SWIM vs Traditional Heartbeating:**

| Aspect | Traditional Heartbeat | SWIM/Gossip |
|--------|----------------------|-------------|
| Network load | O(N²) | O(N) |
| Failure detection | Centralized | Decentralized |
| Single point of failure | Yes | No |
| Cross-subnet | Yes | Yes |

#### HashiCorp Memberlist

[HashiCorp memberlist](https://github.com/hashicorp/memberlist) is a production-ready Go implementation of SWIM with extensions:

- **Lifeguard extensions** - Robust against slow message processing
- **Suspicion mechanism** - Reduces false positives
- **Encryption support** - AES-GCM for gossip messages
- **Used by**: Consul, Nomad, Serf

```go
import "github.com/hashicorp/memberlist"

// Create memberlist with default LAN config
config := memberlist.DefaultLANConfig()
config.Name = agentID
config.BindPort = 7946

list, err := memberlist.Create(config)

// Join existing cluster
list.Join([]string{"10.1.0.5:7946", "10.2.0.10:7946"})

// Get all members
for _, member := range list.Members() {
    fmt.Printf("Member: %s %s\n", member.Name, member.Addr)
}
```

#### HashiCorp Serf

[Serf](https://github.com/hashicorp/serf) builds on memberlist, adding:

- Event propagation (deploy triggers, config changes)
- Query/response mechanism
- Tags for metadata
- [Vivaldi coordinates](https://medium.com/@jesustinoco/the-swim-membership-protocol-fffa2991cb1c) for latency estimation

#### Proposed Gossip Implementation for MAG

```
┌─────────────────────────────────────────────────────────────────┐
│                     Bootstrap Server                             │
│  GET /api/peers - Returns recently active agents as seeds       │
└─────────────────────────────────────────────────────────────────┘
         │ Initial seed peers
         ▼
┌──────────────┐     Gossip      ┌──────────────┐     Gossip
│  Agent A     │◄───────────────►│  Agent B     │◄──────────────►...
│  10.1.0.5    │                 │  10.2.0.10   │
│  Peers: [B,C]│                 │  Peers: [A,D]│
└──────────────┘                 └──────────────┘
     Subnet 1                        Subnet 2
```

**Configuration:**
```json
{
  "pow_discovery_mode": "gossip",
  "pow_gossip_interval": 30,
  "pow_gossip_fanout": 3,
  "pow_max_peers": 50,
  "pow_peer_ttl": 300,
  "pow_seed_url": "https://bootstrap:8443/api/peers"
}
```

**Protocol:**
1. **Bootstrap**: Agent fetches seed peers from bootstrap server
2. **Gossip round**: Every N seconds, contact K random peers
3. **Exchange**: Send partial peer list, receive theirs
4. **Merge**: Add new peers, update timestamps
5. **Evict**: Remove peers not seen for > TTL

---

### Option 2: Kademlia DHT

[Kademlia](https://en.wikipedia.org/wiki/Kademlia) is a distributed hash table used by libp2p, IPFS, and BitTorrent.

**Key concepts:**
- Nodes have 160-bit IDs (SHA-1 hash)
- XOR distance metric for routing
- k-buckets organize peers by distance
- O(log N) lookups

**How it works for discovery:**
- Each agent publishes its info to the DHT at `hash(agent_id)`
- To find witnesses, query DHT for nearby agent IDs
- [libp2p Kademlia DHT](https://docs.libp2p.io/concepts/discovery-routing/kaddht/) provides ready implementation

**Pros:**
- Proven at massive scale (millions of nodes)
- Self-organizing, no central coordination
- Content-addressable routing

**Cons:**
- More complex than gossip
- Higher latency for lookups
- Requires bootstrap nodes

**Best for:**
- Very large deployments (thousands of agents)
- Geo-distributed networks
- When content routing is also needed

---

### Option 3: Central Registry (Bootstrap Server)

Use the bootstrap server as the source of truth for active agents:

```
Agent A                    Bootstrap Server                    Agent B
   │                             │                                │
   │─── POST /registration ─────►│                                │
   │    (include PoW port)       │                                │
   │                             │◄─── POST /registration ────────│
   │                             │                                │
   │─── GET /api/witnesses ─────►│                                │
   │◄── [{B, 10.2.0.10:9100}] ───│                                │
   │                             │                                │
   │─── WitnessRequest ──────────┼───────────────────────────────►│
   │◄── WitnessStatement ────────┼────────────────────────────────│
```

**Configuration:**
```json
{
  "pow_discovery_mode": "registry",
  "pow_registry_url": "https://bootstrap:8443/api/witnesses"
}
```

**Bootstrap Server Endpoint:**
```go
// GET /api/witnesses?limit=10&exclude=self-agent-id
// Returns agents with PoW enabled, seen in last 5 minutes
// Optionally: prefer agents from different subnets
```

**Pros:**
- Simplest implementation
- Centralized control over witness selection
- Can implement smart selection (subnet diversity, load balancing)

**Cons:**
- Single point of failure
- Requires bootstrap server availability
- Doesn't work if server is down

**Best for:**
- Controlled environments
- When bootstrap server HA is guaranteed
- Simpler deployments

---

### Option 4: Hybrid Approach

Combine multiple mechanisms for resilience:

```go
func (d *Discovery) GetWitnesses(count int) []*PeerInfo {
    var witnesses []*PeerInfo

    // 1. Prefer local mDNS neighbors (lowest latency)
    local := d.mdns.GetReachableNeighbors(5 * time.Minute)
    witnesses = append(witnesses, local...)

    // 2. Fill with gossip peers (cross-subnet)
    if len(witnesses) < count {
        remote := d.gossip.GetReachablePeers(5 * time.Minute)
        witnesses = append(witnesses, remote...)
    }

    // 3. Fallback to registry if needed
    if len(witnesses) < count {
        registry := d.registry.GetWitnesses(count - len(witnesses))
        witnesses = append(witnesses, registry...)
    }

    return witnesses[:min(len(witnesses), count)]
}
```

**Configuration:**
```json
{
  "pow_discovery_mode": "hybrid",
  "pow_prefer_local": true,
  "pow_mdns_enabled": true,
  "pow_gossip_enabled": true,
  "pow_registry_enabled": true,
  "pow_registry_url": "https://bootstrap:8443/api/witnesses"
}
```

---

## Comparison Matrix

| Feature | mDNS | Gossip (SWIM) | Kademlia DHT | Central Registry |
|---------|------|---------------|--------------|------------------|
| Cross-subnet | No | Yes | Yes | Yes |
| Scalability | Low | High | Very High | Medium |
| Convergence | Instant | O(log N) | O(log N) | Instant |
| Failure tolerance | N/A | High | High | Low (SPOF) |
| Implementation complexity | Low | Medium | High | Low |
| Bootstrap required | No | Seeds only | Bootstrap nodes | Always |
| Network overhead | Multicast | O(N) unicast | O(log N) | Per-request |
| Latency | Very low | Low | Medium | Depends on server |

---

## Configuration Reference

### PoW Settings

```json
{
  "pow_enabled": true,
  "pow_chain_enabled": true,
  "pow_work_enabled": true,
  "pow_witness_enabled": true,
  "pow_metrics_enabled": true,
  "pow_difficulty": 16,
  "pow_max_work_time_ms": 1000,
  "pow_witness_threshold": 2,
  "pow_witness_timeout": "5s"
}
```

### mDNS Discovery (Current)

```json
{
  "pow_mdns_enabled": true,
  "pow_mdns_service": "_mag-agent._tcp",
  "pow_mdns_domain": "local.",
  "pow_mdns_ipv4_only": false,
  "pow_discovery_interval": 60
}
```

### Gossip Discovery (Proposed)

```json
{
  "pow_discovery_mode": "gossip",
  "pow_gossip_bind_port": 7946,
  "pow_gossip_interval": 30,
  "pow_gossip_fanout": 3,
  "pow_gossip_max_peers": 50,
  "pow_gossip_peer_ttl": 300,
  "pow_gossip_seed_url": "https://bootstrap:8443/api/peers",
  "pow_gossip_encrypt": true,
  "pow_gossip_secret": "base64-encoded-32-byte-key"
}
```

---

## Security Considerations

### Attack Vectors and Mitigations

| Attack | Mitigation |
|--------|------------|
| Fake agent registration | PoW difficulty + witness threshold |
| Replay old heartbeats | Sequence numbers + chain verification |
| Witness collusion | Require witnesses from different subnets |
| Man-in-the-middle | Ed25519 signatures on all messages |
| Denial of service | PoW limits request rate |
| Hardware spoofing | Multiple metric cross-validation |

### Witness Selection Best Practices

1. **Subnet diversity**: Prefer witnesses from different network segments
2. **Rotation**: Periodically change witness set
3. **Minimum threshold**: Require at least 2 witnesses
4. **Freshness**: Only accept recent witness statements (< 5 minutes)

---

## Verification on Bootstrap Server

The bootstrap server verifies SecureHeartbeats:

```go
type VerificationResult struct {
    Valid            bool     // Overall validity
    ChainValid       bool     // Proof chain is continuous
    WorkValid        bool     // PoW meets difficulty
    MetricsValid     bool     // System metrics are consistent
    WitnessCount     int      // Number of valid witnesses
    WitnessThreshold int      // Required witnesses
    Errors           []string // Validation errors
    Warnings         []string // Non-fatal warnings
}
```

**Verification steps:**
1. Verify Ed25519 signature
2. Check sequence number > previous
3. Verify chain hash links correctly
4. Validate PoW hash meets difficulty
5. Check system metrics consistency
6. Verify witness signatures
7. Ensure witness threshold met

---

## Recommendations

### Small Deployments (< 50 agents, single subnet)
- **Use**: mDNS only
- **Why**: Simple, zero configuration, instant discovery

### Medium Deployments (50-500 agents, multiple subnets)
- **Use**: Gossip (memberlist) + mDNS hybrid
- **Why**: Cross-subnet discovery with local preference

### Large Deployments (500+ agents, geo-distributed)
- **Use**: Gossip with central registry fallback
- **Why**: Scalable, resilient, centralized control when needed

### High-Security Environments
- **Use**: Central registry with strict witness selection
- **Why**: Controlled witness selection, audit trail

---

## References

### Academic Papers
- [SWIM: Scalable Weakly-consistent Infection-style Process Group Membership Protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf) - Cornell University, 2002
- [Kademlia: A Peer-to-peer Information System Based on the XOR Metric](https://en.wikipedia.org/wiki/Kademlia) - Maymounkov & Mazières, 2002

### Implementations
- [HashiCorp memberlist](https://github.com/hashicorp/memberlist) - Go SWIM implementation
- [HashiCorp Serf](https://github.com/hashicorp/serf) - Service orchestration on memberlist
- [libp2p Kademlia DHT](https://docs.libp2p.io/concepts/discovery-routing/kaddht/) - P2P networking stack

### Protocols
- [RFC 6762 - Multicast DNS](https://datatracker.ietf.org/doc/html/rfc6762)
- [RFC 6763 - DNS-Based Service Discovery](https://www.dns-sd.org/)

### Further Reading
- [SWIM Protocol Explained](https://www.brianstorti.com/swim/)
- [Gossip, Serf, memberlist, Raft, and SWIM in HashiCorp Consul](https://www.hashicorp.com/en/resources/everybody-talks-gossip-serf-memberlist-raft-swim-hashicorp-consul)
- [Creating Distributed Systems Using Memberlist](https://dev.to/davidsbond/golang-creating-distributed-systems-using-memberlist-2fa9)
- [libp2p Peer Discovery](https://docs.libp2p.io/concepts/discovery-routing/kaddht/)
