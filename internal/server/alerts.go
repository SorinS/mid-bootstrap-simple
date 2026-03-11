package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"mid-bootstrap-server.git/internal/store"
	"mid-bootstrap-server.git/internal/types"
)

// AlertService handles alert detection and management
type AlertService struct {
	store             store.Store
	staleAgentMinutes int
	enableWebSocket   bool

	// Callbacks for WebSocket notifications
	onNewAlert func(*types.Alert)

	mu sync.RWMutex
}

// NewAlertService creates a new alert service
func NewAlertService(s store.Store, staleAgentMinutes int) *AlertService {
	if staleAgentMinutes <= 0 {
		staleAgentMinutes = 10 // Default: 10 minutes
	}
	return &AlertService{
		store:             s,
		staleAgentMinutes: staleAgentMinutes,
	}
}

// SetWebSocketCallback sets the callback for new alert notifications
func (as *AlertService) SetWebSocketCallback(callback func(*types.Alert)) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.onNewAlert = callback
}

// StartStaleAgentChecker starts a background goroutine to check for stale agents
func (as *AlertService) StartStaleAgentChecker(ctx context.Context, checkInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		// Initial check
		as.CheckStaleAgents()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				as.CheckStaleAgents()
			}
		}
	}()
}

// CheckStaleAgents checks for agents that haven't sent heartbeats recently
func (as *AlertService) CheckStaleAgents() {
	registrations := as.store.ListRegistrations()
	cutoff := time.Now().Add(-time.Duration(as.staleAgentMinutes) * time.Minute)

	for _, reg := range registrations {
		if reg.LastSeenAt.Before(cutoff) {
			// Check if we already have ANY stale alert for this agent (resolved or not)
			// We only create a new alert if:
			// 1. No existing alert exists for this agent/version, OR
			// 2. The existing alert was created BEFORE the agent's last heartbeat (meaning agent recovered and went stale again)
			existing, _ := as.store.GetAlertByAgentVersion(reg.AgentID, reg.AgentVersion)
			if existing != nil {
				// If alert is unresolved, skip
				if !existing.Resolved {
					continue
				}
				// If alert is resolved but was created AFTER the last heartbeat, skip
				// (this means we already handled this stale period)
				if existing.CreatedAt.After(reg.LastSeenAt) {
					continue
				}
			}

			staleDuration := int(time.Since(reg.LastSeenAt).Minutes())
			alert := &types.Alert{
				Type:             types.AlertTypeStaleAgent,
				Severity:         types.AlertSeverityWarning,
				AgentID:          reg.AgentID,
				Hostname:         reg.Hostname,
				AgentVersion:     reg.AgentVersion,
				Message:          fmt.Sprintf("Agent %s has not sent heartbeat for %d minutes", reg.Hostname, staleDuration),
				LastSeenAt:       &reg.LastSeenAt,
				StaleDurationMin: staleDuration,
			}

			if err := as.store.AddAlert(alert); err != nil {
				log.Printf("[AlertService] Failed to add stale agent alert: %v", err)
				continue
			}

			as.notifyNewAlert(alert)
			log.Printf("[AlertService] Created stale agent alert for %s (last seen %s)", reg.Hostname, reg.LastSeenAt.Format(time.RFC3339))
		}
	}
}

// CheckVersionChange checks if an agent has changed versions and creates alerts for old versions
// This should be called during registration processing
func (as *AlertService) CheckVersionChange(newReg *types.AgentRegistration) {
	// Get all registrations for this hostname
	allRegs := as.store.GetAllRegistrationsByHostname(newReg.Hostname)

	for _, oldReg := range allRegs {
		// Skip if same version or same agent ID
		if oldReg.AgentVersion == newReg.AgentVersion || oldReg.AgentID == newReg.AgentID {
			continue
		}

		// Check if we already have an alert for this old version
		existing, _ := as.store.GetAlertByAgentVersion(oldReg.AgentID, oldReg.AgentVersion)
		if existing != nil {
			continue // Already have an alert
		}

		alert := &types.Alert{
			Type:         types.AlertTypeVersionChange,
			Severity:     types.AlertSeverityInfo,
			AgentID:      oldReg.AgentID,
			Hostname:     oldReg.Hostname,
			AgentVersion: oldReg.AgentVersion,
			Message:      fmt.Sprintf("Agent %s upgraded from %s to %s", oldReg.Hostname, oldReg.AgentVersion, newReg.AgentVersion),
			OldVersion:   oldReg.AgentVersion,
			NewVersion:   newReg.AgentVersion,
			LastSeenAt:   &oldReg.LastSeenAt,
		}

		if err := as.store.AddAlert(alert); err != nil {
			log.Printf("[AlertService] Failed to add version change alert: %v", err)
			continue
		}

		as.notifyNewAlert(alert)
		log.Printf("[AlertService] Created version change alert for %s: %s -> %s", oldReg.Hostname, oldReg.AgentVersion, newReg.AgentVersion)
	}
}

// ResolveStaleAlertIfActive resolves a stale agent alert when the agent sends a heartbeat
func (as *AlertService) ResolveStaleAlertIfActive(agentID string) {
	alerts := as.store.ListAlertsByType(types.AlertTypeStaleAgent)
	for _, alert := range alerts {
		if alert.AgentID == agentID && !alert.Resolved {
			as.store.ResolveAlert(alert.ID, "system", "agent_recovered")
			log.Printf("[AlertService] Resolved stale agent alert for %s - agent recovered", alert.Hostname)
		}
	}
}

// notifyNewAlert sends WebSocket notification for new alerts
func (as *AlertService) notifyNewAlert(alert *types.Alert) {
	as.mu.RLock()
	callback := as.onNewAlert
	as.mu.RUnlock()

	if callback != nil {
		callback(alert)
	}
}

// DeleteOldVersionRegistration deletes an old version registration and deletes its alerts
func (as *AlertService) DeleteOldVersionRegistration(agentID string, resolvedBy string) error {
	// Try to get the registration (may not exist if already deleted or AgentID changed)
	reg, err := as.store.GetRegistration(agentID)
	if err != nil {
		// Registration not found - that's OK, we'll still delete the alerts
		log.Printf("[AlertService] Registration not found for %s (may already be deleted): %v", agentID, err)
	} else {
		// Delete the registration if it exists
		if err := as.store.DeleteRegistration(agentID); err != nil {
			log.Printf("[AlertService] Failed to delete registration for %s: %v", agentID, err)
			// Continue to delete alerts even if registration delete failed
		} else {
			log.Printf("[AlertService] Deleted old version registration for %s (version %s)", reg.Hostname, reg.AgentVersion)
		}
	}

	// Find and DELETE any alerts for this agent (not just resolve)
	deletedCount := 0
	alerts := as.store.ListAlerts()
	for _, alert := range alerts {
		if alert.AgentID == agentID {
			if err := as.store.DeleteAlert(alert.ID); err != nil {
				log.Printf("[AlertService] Failed to delete alert %s: %v", alert.ID, err)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		log.Printf("[AlertService] Deleted %d alerts for agent %s", deletedCount, agentID)
	}

	return nil
}
