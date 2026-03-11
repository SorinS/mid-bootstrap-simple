package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"mid-bootstrap-server.git/internal/types"
)

// EventType represents the type of WebSocket event
type EventType string

const (
	EventNewRequest      EventType = "new_request"
	EventRequestApproved EventType = "request_approved"
	EventRequestDenied   EventType = "request_denied"
	EventRequestDeleted  EventType = "request_deleted"
	EventTokenGenerated  EventType = "token_generated"
	EventAgentRegistered EventType = "agent_registered"

	// PoW (Proof of Work) anti-spoofing events
	EventPoWVerified EventType = "pow_verified" // PoW verification passed
	EventPoWWarning  EventType = "pow_warning"  // PoW verification has warnings
	EventPoWFailed   EventType = "pow_failed"   // PoW verification failed (possible spoofing)

	// Alert events
	EventNewAlert        EventType = "new_alert"         // New alert created (stale agent, version change)
	EventAlertAcknowledged EventType = "alert_acknowledged" // Alert acknowledged by operator
	EventAlertResolved   EventType = "alert_resolved"    // Alert resolved (agent recovered, old version deleted)
)

// WebSocketEvent represents an event sent to WebSocket clients
type WebSocketEvent struct {
	Type      EventType   `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// WebSocketHub manages WebSocket connections and broadcasts events
type WebSocketHub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan WebSocketEvent
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.RWMutex
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan WebSocketEvent, 100),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
}

// Run starts the hub's main loop
func (h *WebSocketHub) Run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()
			log.Printf("[WebSocket] Client connected (total: %d)", len(h.clients))

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()
			log.Printf("[WebSocket] Client disconnected (total: %d)", len(h.clients))

		case event := <-h.broadcast:
			h.mu.RLock()
			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("[WebSocket] Failed to marshal event: %v", err)
				h.mu.RUnlock()
				continue
			}

			for conn := range h.clients {
				err := conn.WriteMessage(websocket.TextMessage, data)
				if err != nil {
					log.Printf("[WebSocket] Write error: %v", err)
					conn.Close()
					delete(h.clients, conn)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends an event to all connected clients
func (h *WebSocketHub) Broadcast(eventType EventType, data interface{}) {
	event := WebSocketEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	select {
	case h.broadcast <- event:
	default:
		log.Printf("[WebSocket] Broadcast channel full, dropping event")
	}
}

// ClientCount returns the number of connected clients
func (h *WebSocketHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// BroadcastAlert sends an alert event to all connected clients
func (h *WebSocketHub) BroadcastAlert(alert *types.Alert) {
	data := AlertEventData{
		AlertID:      alert.ID,
		Type:         string(alert.Type),
		Severity:     string(alert.Severity),
		Hostname:     alert.Hostname,
		AgentID:      alert.AgentID,
		AgentVersion: alert.AgentVersion,
		Message:      alert.Message,
		OldVersion:   alert.OldVersion,
		NewVersion:   alert.NewVersion,
	}
	h.Broadcast(EventNewAlert, data)
}

// WebSocket upgrader with reasonable defaults
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from same origin
		return true
	},
}

// handleWebSocket handles WebSocket connection requests
// @Summary WebSocket connection for real-time updates
// @Description Establishes a WebSocket connection for receiving real-time events. Events include: new_request, request_approved, request_denied, token_generated, new_alert, alert_acknowledged, alert_resolved. Messages are JSON formatted with 'type' and 'data' fields.
// @Tags websocket
// @Success 101 {string} string "Switching Protocols - WebSocket connection established"
// @Failure 400 {string} string "Bad Request - WebSocket upgrade failed"
// @Router /ws [get]
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebSocket] Upgrade error: %v", err)
		return
	}

	s.wsHub.register <- conn

	// Send initial state
	s.sendInitialState(conn)

	// Keep connection alive and handle disconnection
	go func() {
		defer func() {
			s.wsHub.unregister <- conn
		}()

		// Set read deadline for ping/pong
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})

		// Read loop (handles client messages and detects disconnection)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("[WebSocket] Read error: %v", err)
				}
				break
			}
		}
	}()

	// Ping loop to keep connection alive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()
}

// sendInitialState sends the current state to a newly connected client
func (s *Server) sendInitialState(conn *websocket.Conn) {
	stats := s.store.Stats()
	initialState := struct {
		Type  string                  `json:"type"`
		Stats *types.DashboardStats   `json:"stats"`
	}{
		Type:  "initial_state",
		Stats: stats,
	}

	data, err := json.Marshal(initialState)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal initial state: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		log.Printf("[WebSocket] Failed to send initial state: %v", err)
	}
}

// Event data structures for WebSocket messages

// RequestEventData contains data about a bootstrap request event
type RequestEventData struct {
	RequestID  string `json:"request_id"`
	Hostname   string `json:"hostname"`
	ClientIP   string `json:"client_ip,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Status     string `json:"status,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
	DeniedBy   string `json:"denied_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
	TokenID    string `json:"token_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// AgentEventData contains data about an agent registration event
type AgentEventData struct {
	AgentID   string `json:"agent_id"`
	Hostname  string `json:"hostname"`
	ClientIP  string `json:"client_ip"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	IsNew     bool   `json:"is_new"`
}

// PoWEventData contains data about a PoW verification event
type PoWEventData struct {
	AgentID          string   `json:"agent_id"`
	Hostname         string   `json:"hostname"`
	ClientIP         string   `json:"client_ip"`
	Status           string   `json:"status"`                      // "ok", "warning", "failed"
	ChainValid       bool     `json:"chain_valid"`
	WorkValid        bool     `json:"work_valid"`
	MetricsValid     bool     `json:"metrics_valid"`
	WitnessCount     int      `json:"witness_count"`
	WitnessThreshold int      `json:"witness_threshold"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	Sequence         uint64   `json:"sequence,omitempty"`          // Heartbeat sequence number
}

// AlertEventData contains data about an alert event
type AlertEventData struct {
	AlertID      string `json:"alert_id"`
	Type         string `json:"type"`     // "stale_agent", "version_change"
	Severity     string `json:"severity"` // "info", "warning", "critical"
	Hostname     string `json:"hostname"`
	AgentID      string `json:"agent_id"`
	AgentVersion string `json:"agent_version,omitempty"`
	Message      string `json:"message"`
	OldVersion   string `json:"old_version,omitempty"` // For version_change alerts
	NewVersion   string `json:"new_version,omitempty"` // For version_change alerts
}
