package server

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"mid-bootstrap-server.git/internal/types"
)

// handleListAlerts returns all alerts as JSON
// @Summary List all alerts
// @Description Returns a list of all alerts, newest first
// @Tags alerts
// @Produce json
// @Success 200 {array} types.Alert "List of alerts"
// @Router /api/alerts [get]
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	alerts := s.store.ListAlerts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// handleAlert handles individual alert operations (GET, POST acknowledge/resolve, DELETE)
// @Summary Get, update, or delete an alert
// @Description Handles individual alert operations: GET retrieves alert details, POST performs actions (acknowledge, resolve, delete-agent), DELETE removes the alert
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path string true "Alert ID"
// @Param action path string false "Action to perform: acknowledge, resolve, or delete-agent (POST only)"
// @Param resolution body object false "Resolution details for resolve action" example({"resolution": "manually_resolved"})
// @Success 200 {object} types.Alert "Alert details (GET) or action result (POST/DELETE)"
// @Failure 400 {string} string "Invalid request"
// @Failure 404 {string} string "Alert not found"
// @Router /api/alerts/{id} [get]
// @Router /api/alerts/{id} [delete]
// @Router /api/alerts/{id}/{action} [post]
func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	// Extract alert ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	parts := strings.Split(path, "/")
	alertID := parts[0]

	if alertID == "" {
		http.Error(w, "Alert ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		alert, err := s.store.GetAlert(alertID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alert)

	case http.MethodPost:
		// Handle actions: acknowledge, resolve, delete-agent
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}

		switch action {
		case "acknowledge":
			if err := s.store.AcknowledgeAlert(alertID, "operator"); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			// Broadcast to WebSocket clients
			s.wsHub.Broadcast(EventAlertAcknowledged, map[string]string{"alert_id": alertID})
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "acknowledged"})

		case "resolve":
			var req struct {
				Resolution string `json:"resolution"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				req.Resolution = "manually_resolved"
			}
			if err := s.store.ResolveAlert(alertID, "operator", req.Resolution); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			s.wsHub.Broadcast(EventAlertResolved, map[string]string{"alert_id": alertID})
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "resolved"})

		case "delete-agent":
			// Get the alert to find the agent ID
			alert, err := s.store.GetAlert(alertID)
			if err != nil {
				log.Printf("[Alerts] Alert not found: %s - %v", alertID, err)
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			log.Printf("[Alerts] Deleting old version - AlertID: %s, AgentID: %s, Hostname: %s, Version: %s",
				alertID, alert.AgentID, alert.Hostname, alert.AgentVersion)

			// Delete the old version registration and its alerts
			if err := s.alertService.DeleteOldVersionRegistration(alert.AgentID, "operator"); err != nil {
				log.Printf("[Alerts] Error in DeleteOldVersionRegistration: %v", err)
			}

			// Also make sure THIS specific alert is deleted by ID
			log.Printf("[Alerts] Deleting alert by ID: %s", alertID)
			if err := s.store.DeleteAlert(alertID); err != nil {
				log.Printf("[Alerts] Failed to delete alert %s: %v", alertID, err)
			} else {
				log.Printf("[Alerts] Successfully deleted alert %s", alertID)
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "agent_deleted"})

		default:
			http.Error(w, "Unknown action", http.StatusBadRequest)
		}

	case http.MethodDelete:
		if err := s.store.DeleteAlert(alertID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAlertStats returns alert statistics
// @Summary Get alert statistics
// @Description Returns statistics about alerts
// @Tags alerts
// @Produce json
// @Success 200 {object} types.AlertStats "Alert statistics"
// @Router /api/alert-stats [get]
func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.store.AlertStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAlertsDashboard serves the alerts web dashboard
func (s *Server) handleAlertsDashboard(w http.ResponseWriter, r *http.Request) {
	alerts := s.store.ListAlerts()
	stats := s.store.AlertStats()

	data := struct {
		Alerts []*types.Alert
		Stats  *types.AlertStats
		Config struct {
			StaleAgentMinutes int
		}
	}{
		Alerts: alerts,
		Stats:  stats,
	}
	data.Config.StaleAgentMinutes = s.config.AlertStaleAgentMinutes
	if data.Config.StaleAgentMinutes <= 0 {
		data.Config.StaleAgentMinutes = 10
	}

	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"formatTimePtr": func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		"timeSince": func(t time.Time) string {
			d := time.Since(t)
			if d < time.Minute {
				return "just now"
			}
			if d < time.Hour {
				return d.Truncate(time.Minute).String()
			}
			if d < 24*time.Hour {
				return d.Truncate(time.Hour).String()
			}
			return d.Truncate(24 * time.Hour).String()
		},
	}

	tmpl, err := template.New("alerts").Funcs(funcMap).Parse(alertsDashboardTemplate)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

const alertsDashboardTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Alerts - Bootstrap Server</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/svg+xml" href="/favicon.ico">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 24px; }
        .nav-links { display: flex; gap: 15px; }
        .nav-links a { color: white; text-decoration: none; padding: 8px 16px; background: rgba(255,255,255,0.1); border-radius: 4px; }
        .nav-links a:hover { background: rgba(255,255,255,0.2); }
        .nav-links a.active { background: rgba(255,255,255,0.3); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-card .number { font-size: 36px; font-weight: bold; color: #1a1a2e; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .stat-card.warning .number { color: #f39c12; }
        .stat-card.info .number { color: #3498db; }
        .section { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section-header { padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .section-header h2 { font-size: 18px; color: #333; }
        .filters { display: flex; gap: 10px; padding: 15px 20px; border-bottom: 1px solid #eee; flex-wrap: wrap; align-items: center; }
        .filters select { background: white; border: 1px solid #ddd; color: #333; padding: 8px 12px; border-radius: 4px; font-size: 14px; }
        .filters label { color: #666; font-size: 14px; }
        .filters .threshold { color: #666; margin-left: auto; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #333; }
        tr:hover { background: #f8f9fa; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
        .badge-stale_agent { background: #fff3cd; color: #856404; }
        .badge-version_change { background: #d1ecf1; color: #0c5460; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .badge-critical { background: #f8d7da; color: #721c24; }
        .badge-acknowledged { background: #d4edda; color: #155724; }
        .badge-resolved { background: #e2e3e5; color: #383d41; }
        .badge-pending { background: #fff3cd; color: #856404; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; transition: background 0.2s; }
        .btn-ack { background: #27ae60; color: white; }
        .btn-ack:hover { background: #219a52; }
        .btn-resolve { background: #3498db; color: white; }
        .btn-resolve:hover { background: #2980b9; }
        .btn-delete { background: #e74c3c; color: white; }
        .btn-delete:hover { background: #c0392b; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .actions { white-space: nowrap; }
        .actions .btn { margin-left: 5px; padding: 6px 12px; font-size: 13px; }
        .actions .btn:first-child { margin-left: 0; }
        .empty { padding: 40px; text-align: center; color: #999; }
        .message { padding: 12px 20px; margin-bottom: 15px; border-radius: 4px; color: white; }
        .message.success { background: #27ae60; }
        .message.error { background: #e74c3c; }
        .machine-info { font-size: 12px; color: #666; }
        .detail-text { font-size: 12px; color: #666; margin-top: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Alerts</h1>
            <nav class="nav-links">
                <a href="/">Bootstrap Requests</a>
                <a href="/system">Registered Agents</a>
                <a href="/alerts" class="active">Alerts</a>
                <a href="/manual-bootstrap">Manual Bootstrap</a>
                <a href="/audit">Audit Log</a>
            </nav>
        </header>

        <div id="message" class="message" style="display: none;"></div>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{{.Stats.TotalAlerts}}</div>
                <div class="label">Total Alerts</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{{.Stats.UnacknowledgedCount}}</div>
                <div class="label">Unacknowledged</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{{.Stats.StaleAgentCount}}</div>
                <div class="label">Stale Agents</div>
            </div>
            <div class="stat-card info">
                <div class="number">{{.Stats.VersionChangeCount}}</div>
                <div class="label">Version Changes</div>
            </div>
        </div>

        <div class="section">
            <div class="filters">
                <label>Type:</label>
                <select id="typeFilter" onchange="filterAlerts()">
                    <option value="all">All Types</option>
                    <option value="stale_agent">Stale Agents</option>
                    <option value="version_change">Version Changes</option>
                </select>
                <label>Status:</label>
                <select id="statusFilter" onchange="filterAlerts()">
                    <option value="all">All Status</option>
                    <option value="unacknowledged">Unacknowledged</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="resolved">Resolved</option>
                </select>
                <span class="threshold">Stale threshold: {{.Config.StaleAgentMinutes}} minutes</span>
            </div>

            {{if .Alerts}}
            <table id="alertsTable">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Hostname</th>
                        <th>Message</th>
                        <th>Created</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Alerts}}
                    <tr data-type="{{.Type}}" data-ack="{{.Acknowledged}}" data-resolved="{{.Resolved}}">
                        <td><span class="badge badge-{{.Type}}">{{.Type}}</span></td>
                        <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
                        <td>
                            <strong>{{.Hostname}}</strong>
                            {{if .AgentVersion}}<div class="machine-info">v{{.AgentVersion}}</div>{{end}}
                        </td>
                        <td>
                            {{.Message}}
                            {{if .OldVersion}}<div class="detail-text">{{.OldVersion}} → {{.NewVersion}}</div>{{end}}
                            {{if .LastSeenAt}}<div class="detail-text">Last seen: {{formatTimePtr .LastSeenAt}}</div>{{end}}
                        </td>
                        <td>{{formatTime .CreatedAt}}</td>
                        <td>
                            {{if .Resolved}}
                                <span class="badge badge-resolved">Resolved</span>
                                {{if .ResolvedBy}}<div class="machine-info">by {{.ResolvedBy}}</div>{{end}}
                            {{else if .Acknowledged}}
                                <span class="badge badge-acknowledged">Acknowledged</span>
                                {{if .AcknowledgedBy}}<div class="machine-info">by {{.AcknowledgedBy}}</div>{{end}}
                            {{else}}
                                <span class="badge badge-pending">Pending</span>
                            {{end}}
                        </td>
                        <td class="actions">
                            {{if not .Acknowledged}}
                            <button class="btn btn-ack" onclick="acknowledgeAlert('{{.ID}}')">Ack</button>
                            {{end}}
                            {{if not .Resolved}}
                            <button class="btn btn-resolve" onclick="resolveAlert('{{.ID}}')">Resolve</button>
                            {{end}}
                            {{if eq .Type "version_change"}}
                            <button class="btn btn-delete" onclick="deleteOldVersion('{{.ID}}', '{{.Hostname}}', '{{.AgentVersion}}')" title="Delete old version registration">Delete Old</button>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="empty">No alerts. All systems are operating normally.</div>
            {{end}}
        </div>
    </div>

    <script>
        function showMessage(text, type) {
            const msg = document.getElementById('message');
            msg.textContent = text;
            msg.className = 'message ' + type;
            msg.style.display = 'block';
            setTimeout(() => msg.style.display = 'none', 3000);
        }

        async function acknowledgeAlert(id) {
            try {
                const resp = await fetch('/api/alerts/' + id + '/acknowledge', { method: 'POST' });
                if (resp.ok) {
                    showMessage('Alert acknowledged', 'success');
                    setTimeout(() => location.reload(), 500);
                } else {
                    showMessage('Failed to acknowledge alert', 'error');
                }
            } catch (e) {
                showMessage('Error: ' + e.message, 'error');
            }
        }

        async function resolveAlert(id) {
            try {
                const resp = await fetch('/api/alerts/' + id + '/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ resolution: 'manually_resolved' })
                });
                if (resp.ok) {
                    showMessage('Alert resolved', 'success');
                    setTimeout(() => location.reload(), 500);
                } else {
                    showMessage('Failed to resolve alert', 'error');
                }
            } catch (e) {
                showMessage('Error: ' + e.message, 'error');
            }
        }

        async function deleteOldVersion(alertId, hostname, version) {
            if (!confirm('Delete old version registration for ' + hostname + ' v' + version + '?')) {
                return;
            }
            try {
                const resp = await fetch('/api/alerts/' + alertId + '/delete-agent', { method: 'POST' });
                if (resp.ok) {
                    showMessage('Old version deleted', 'success');
                    setTimeout(() => location.reload(), 500);
                } else {
                    showMessage('Failed to delete old version', 'error');
                }
            } catch (e) {
                showMessage('Error: ' + e.message, 'error');
            }
        }

        function filterAlerts() {
            const typeFilter = document.getElementById('typeFilter').value;
            const statusFilter = document.getElementById('statusFilter').value;
            const rows = document.querySelectorAll('#alertsTable tbody tr');

            rows.forEach(row => {
                const type = row.dataset.type;
                const ack = row.dataset.ack === 'true';
                const resolved = row.dataset.resolved === 'true';

                let show = true;
                if (typeFilter !== 'all' && type !== typeFilter) show = false;
                if (statusFilter === 'unacknowledged' && (ack || resolved)) show = false;
                if (statusFilter === 'acknowledged' && (!ack || resolved)) show = false;
                if (statusFilter === 'resolved' && !resolved) show = false;

                row.style.display = show ? '' : 'none';
            });
        }

        // WebSocket for real-time updates
        function connectWebSocket() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(protocol + '//' + location.host + '/ws');

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (data.type === 'new_alert' || data.type === 'alert_acknowledged' || data.type === 'alert_resolved') {
                    location.reload();
                }
            };

            ws.onclose = function() {
                setTimeout(connectWebSocket, 5000);
            };
        }
        connectWebSocket();
    </script>
</body>
</html>`
