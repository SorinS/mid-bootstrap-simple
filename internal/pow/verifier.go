// Package pow provides server-side verification of proof-of-work heartbeats
package pow

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"mid-bootstrap-server.git/internal/types"
)

// Verifier verifies SecureHeartbeat messages from agents
type Verifier struct {
	mu sync.RWMutex

	// Configuration
	difficulty       uint8
	witnessThreshold int
	enabled          bool

	// State tracking per agent
	chains     map[string]*chainState // agent_id -> chain state
	metrics    map[string]*metricsState
	publicKeys map[string]ed25519.PublicKey
}

type chainState struct {
	lastSeq  uint64
	lastHash []byte
	lastSeen time.Time
}

type metricsState struct {
	bootID    string
	machineID string
	lastSeen  time.Time
}

// NewVerifier creates a new PoW verifier
func NewVerifier(difficulty uint8, witnessThreshold int) *Verifier {
	if difficulty == 0 {
		difficulty = 16
	}
	if witnessThreshold == 0 {
		witnessThreshold = 2
	}
	return &Verifier{
		difficulty:       difficulty,
		witnessThreshold: witnessThreshold,
		enabled:          true,
		chains:           make(map[string]*chainState),
		metrics:          make(map[string]*metricsState),
		publicKeys:       make(map[string]ed25519.PublicKey),
	}
}

// SetEnabled enables or disables verification
func (v *Verifier) SetEnabled(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = enabled
}

// IsEnabled returns whether verification is enabled
func (v *Verifier) IsEnabled() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.enabled
}

// Verify verifies a SecureHeartbeat and returns the result
func (v *Verifier) Verify(heartbeat *types.SecureHeartbeat) *types.PoWVerificationResult {
	if heartbeat == nil {
		return &types.PoWVerificationResult{
			Valid:  false,
			Errors: []string{"no heartbeat provided"},
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	result := &types.PoWVerificationResult{
		Valid:            true,
		ChainValid:       true,
		WorkValid:        true,
		MetricsValid:     true,
		WitnessThreshold: v.witnessThreshold,
	}

	// Verify chain continuity
	chainResult := v.verifyChain(heartbeat)
	result.ChainValid = chainResult.valid
	if !chainResult.valid {
		result.Errors = append(result.Errors, chainResult.errors...)
	}
	result.Warnings = append(result.Warnings, chainResult.warnings...)

	// Verify proof of work
	if heartbeat.WorkHash != nil {
		workValid := v.verifyWork(heartbeat)
		result.WorkValid = workValid
		if !workValid {
			result.Errors = append(result.Errors, "invalid proof of work")
		}
	}

	// Verify system metrics
	if heartbeat.SystemMetrics != nil {
		metricsResult := v.verifyMetrics(heartbeat)
		result.MetricsValid = metricsResult.valid
		if !metricsResult.valid {
			result.Errors = append(result.Errors, metricsResult.errors...)
		}
		result.Warnings = append(result.Warnings, metricsResult.warnings...)
	}

	// Count valid witnesses
	result.WitnessCount = len(heartbeat.Witnesses)

	// Update overall validity
	result.Valid = result.ChainValid && result.WorkValid && result.MetricsValid

	// Store public key if provided
	if len(heartbeat.PublicKey) == ed25519.PublicKeySize {
		v.publicKeys[heartbeat.AgentID] = heartbeat.PublicKey
	}

	return result
}

type verifyResult struct {
	valid    bool
	errors   []string
	warnings []string
}

func (v *Verifier) verifyChain(heartbeat *types.SecureHeartbeat) verifyResult {
	result := verifyResult{valid: true}

	chain, exists := v.chains[heartbeat.AgentID]
	if !exists {
		// First heartbeat from this agent
		if heartbeat.Sequence != 1 {
			result.warnings = append(result.warnings, "first heartbeat should have sequence 1")
		}
		// Create new chain state
		v.chains[heartbeat.AgentID] = &chainState{
			lastSeq:  heartbeat.Sequence,
			lastHash: v.hashHeartbeat(heartbeat),
			lastSeen: time.Now(),
		}
		return result
	}

	// Check sequence
	expectedSeq := chain.lastSeq + 1
	if heartbeat.Sequence != expectedSeq {
		if heartbeat.Sequence > expectedSeq {
			result.warnings = append(result.warnings, "sequence gap detected - possible missed heartbeats")
		} else if heartbeat.Sequence < expectedSeq {
			result.errors = append(result.errors, "sequence went backwards - possible replay or spoof")
			result.valid = false
		}
	}

	// Check previous hash
	if len(heartbeat.PreviousHash) > 0 && len(chain.lastHash) > 0 {
		if !bytesEqual(heartbeat.PreviousHash, chain.lastHash) {
			result.warnings = append(result.warnings, "previous hash mismatch - chain may be broken")
		}
	}

	// Update chain state
	chain.lastSeq = heartbeat.Sequence
	chain.lastHash = v.hashHeartbeat(heartbeat)
	chain.lastSeen = time.Now()

	return result
}

func (v *Verifier) verifyWork(heartbeat *types.SecureHeartbeat) bool {
	// Prepare input data
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, heartbeat.Sequence)

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(heartbeat.Timestamp))

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, heartbeat.Nonce)

	// Build data to hash
	data := make([]byte, 0, len(heartbeat.AgentID)+8+8+len(heartbeat.PreviousHash)+8)
	data = append(data, []byte(heartbeat.AgentID)...)
	data = append(data, seqBytes...)
	data = append(data, tsBytes...)
	data = append(data, heartbeat.PreviousHash...)
	data = append(data, nonceBytes...)

	// Compute hash
	hash := sha256.Sum256(data)

	// Check hash matches
	if !bytesEqual(hash[:], heartbeat.WorkHash) {
		return false
	}

	// Check difficulty (use heartbeat's difficulty or default)
	difficulty := heartbeat.Difficulty
	if difficulty == 0 {
		difficulty = v.difficulty
	}

	return meetsDifficulty(hash[:], difficulty)
}

func (v *Verifier) verifyMetrics(heartbeat *types.SecureHeartbeat) verifyResult {
	result := verifyResult{valid: true}
	metrics := heartbeat.SystemMetrics

	state, exists := v.metrics[heartbeat.AgentID]
	if !exists {
		// First metrics from this agent
		v.metrics[heartbeat.AgentID] = &metricsState{
			bootID:    metrics.BootID,
			machineID: metrics.MachineID,
			lastSeen:  time.Now(),
		}
		return result
	}

	// Check machine ID consistency
	if state.machineID != "" && metrics.MachineID != "" && state.machineID != metrics.MachineID {
		result.errors = append(result.errors, "machine_id changed - likely different machine")
		result.valid = false
	}

	// Check boot ID
	if state.bootID != "" && metrics.BootID != "" && state.bootID != metrics.BootID {
		result.warnings = append(result.warnings, "boot_id changed - machine may have rebooted")
	}

	// Update state
	state.bootID = metrics.BootID
	state.machineID = metrics.MachineID
	state.lastSeen = time.Now()

	return result
}

func (v *Verifier) hashHeartbeat(heartbeat *types.SecureHeartbeat) []byte {
	// Hash the core fields (excluding signature and merkle root)
	toHash := struct {
		AgentID       string                 `json:"agent_id"`
		Hostname      string                 `json:"hostname"`
		Timestamp     int64                  `json:"timestamp"`
		Sequence      uint64                 `json:"sequence"`
		PreviousHash  []byte                 `json:"previous_hash"`
		Nonce         uint64                 `json:"nonce"`
		Difficulty    uint8                  `json:"difficulty"`
		WorkHash      []byte                 `json:"work_hash"`
		SystemMetrics *types.PoWSystemMetrics `json:"system_metrics,omitempty"`
		TPMQuote      []byte                 `json:"tpm_quote,omitempty"`
	}{
		AgentID:       heartbeat.AgentID,
		Hostname:      heartbeat.Hostname,
		Timestamp:     heartbeat.Timestamp,
		Sequence:      heartbeat.Sequence,
		PreviousHash:  heartbeat.PreviousHash,
		Nonce:         heartbeat.Nonce,
		Difficulty:    heartbeat.Difficulty,
		WorkHash:      heartbeat.WorkHash,
		SystemMetrics: heartbeat.SystemMetrics,
		TPMQuote:      heartbeat.TPMQuote,
	}

	data, _ := json.Marshal(toHash)
	hash := sha256.Sum256(data)
	return hash[:]
}

// GetAgentSequence returns the last known sequence for an agent
func (v *Verifier) GetAgentSequence(agentID string) uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if chain, exists := v.chains[agentID]; exists {
		return chain.lastSeq
	}
	return 0
}

// Helper functions

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func meetsDifficulty(hash []byte, difficulty uint8) bool {
	zeroBits := 0
	for _, b := range hash {
		if b == 0 {
			zeroBits += 8
		} else {
			for i := 7; i >= 0; i-- {
				if (b & (1 << i)) == 0 {
					zeroBits++
				} else {
					break
				}
			}
			break
		}
		if zeroBits >= int(difficulty) {
			return true
		}
	}
	return zeroBits >= int(difficulty)
}
