package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mid-bootstrap-server.git/internal/store"
	"mid-bootstrap-server.git/internal/tpm"
	"mid-bootstrap-server.git/internal/types"
	"mid-bootstrap-server.git/internal/version"
)

// jsonError writes a JSON error response for API endpoints
func jsonError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// handleHealth returns server health status
// @Summary Health check
// @Description Returns the health status of the server
// @Tags Bootstrap
// @Produce json
// @Success 200 {object} map[string]string "Server is healthy"
// @Router /health [get]
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleVersion returns server version information
// @Summary Get server version
// @Description Returns the version information of the bootstrap server
// @Tags Bootstrap
// @Produce json
// @Success 200 {object} map[string]string "Version information"
// @Router /version [get]
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": version.Version,
		"major":   version.Major,
		"minor":   version.Minor,
		"patch":   version.Patch,
		"release": version.Release,
	})
}

// generateTokenForAgent generates the appropriate bootstrap token based on configured bootstrap_type.
// When "token": fetches JWT from source, logs into Vault, returns Vault client token.
// When "certificate" (default): calls MID auth to generate a one-time token.
func (s *Server) generateTokenForAgent(machineReq *types.MachineRequest) (*types.BootstrapToken, string, error) {
	bootstrapType := s.config.BootstrapType
	if bootstrapType == "" {
		bootstrapType = "certificate"
	}

	switch bootstrapType {
	case "token":
		token, err := s.vaultClient.LoginWithJWTForAgent(
			s.config.VaultJWTSource,
			s.config.VaultAuthRole,
			machineReq.Hostname,
		)
		if err != nil {
			return nil, bootstrapType, fmt.Errorf("vault JWT token login failed: %w", err)
		}
		return token, bootstrapType, nil

	case "certificate":
		token, err := s.vaultClient.GenerateBootstrapToken(machineReq)
		if err != nil {
			return nil, bootstrapType, fmt.Errorf("MID token generation failed: %w", err)
		}
		return token, bootstrapType, nil

	default:
		return nil, bootstrapType, fmt.Errorf("unknown bootstrap_type: %s", bootstrapType)
	}
}

// bootstrapResponseType returns the configured bootstrap type for responses
func (s *Server) bootstrapResponseType() string {
	if s.config.BootstrapType == "" {
		return "certificate"
	}
	return s.config.BootstrapType
}

// handleBootstrap handles bootstrap requests from agents
// @Summary Submit bootstrap request
// @Description Agents call this endpoint to request bootstrap enrollment. Returns approval status and token if approved.
// @Tags Bootstrap
// @Accept json
// @Produce json
// @Param os path string true "Operating system (linux, darwin, windows)"
// @Param request body types.AutoBootstrapRequest true "Bootstrap request with machine information"
// @Success 200 {object} types.AutoBootstrapResponse "Bootstrap response with status and optional token"
// @Failure 400 {object} types.AutoBootstrapResponse "Invalid request"
// @Failure 403 {object} types.AutoBootstrapResponse "Request denied"
// @Router /bootstrap/{os}/machine [post]
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the OS from the path: /bootstrap/{os}/machine
	path := strings.TrimPrefix(r.URL.Path, "/bootstrap/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "machine" {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}
	osType := parts[0]

	// Read and parse the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendBootstrapResponse(w, http.StatusBadRequest, &types.AutoBootstrapResponse{
			Status:  "error",
			Message: "Failed to read request body",
		})
		return
	}

	var req types.AutoBootstrapRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.sendBootstrapResponse(w, http.StatusBadRequest, &types.AutoBootstrapResponse{
			Status:  "error",
			Message: "Invalid JSON",
		})
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		s.sendBootstrapResponse(w, http.StatusBadRequest, &types.AutoBootstrapResponse{
			Status:  "error",
			Message: "hostname is required",
		})
		return
	}

	// Set OS from path if not in body
	if req.OS == "" {
		req.OS = osType
	}

	clientIP := getClientIP(r)
	log.Printf("Bootstrap request from %s: hostname=%s, os=%s, arch=%s",
		clientIP, req.Hostname, req.OS, req.Arch)

	// Add or update the request in the store
	machineReq, isNew := s.store.AddOrUpdate(&req, clientIP)

	// Debug logging for request deduplication
	if isNew {
		log.Printf("[DEDUP] NEW request created for %s (id=%s, macs=%v)", req.Hostname, machineReq.ID, req.MACAddresses)
	} else {
		log.Printf("[DEDUP] EXISTING request updated for %s (id=%s, status=%s, requestCount=%d)", req.Hostname, machineReq.ID, machineReq.Status, machineReq.RequestCount)
	}

	// Verify TPM attestation if provided
	tpmVerified := false
	if machineReq.HasTPM && machineReq.TPMAttestation != nil {
		result := tpm.VerifyAttestation(machineReq.TPMAttestation, machineReq.LastNonce)

		// Debug logging
		log.Printf("[TPM] Verification result for %s: Verified=%v, QuoteVerified=%v, NonceVerified=%v",
			req.Hostname, result.Verified, result.QuoteVerified, result.NonceVerified)
		if len(result.Errors) > 0 {
			log.Printf("[TPM] Errors: %v", result.Errors)
		}
		if len(result.Warnings) > 0 {
			log.Printf("[TPM] Warnings: %v", result.Warnings)
		}

		// Update the TPM verification status in the store
		if err := s.store.UpdateTPMVerification(machineReq.ID, result.Verified, result.Errors); err != nil {
			log.Printf("Failed to update TPM verification status: %v", err)
		}

		// Update the local copy for immediate use
		machineReq.TPMAttestation.Verified = result.Verified
		machineReq.TPMAttestation.VerifyErrors = result.Errors

		// For auto-approval, we require the quote signature to be verified
		// (QuoteVerified means the AK signature is valid)
		if result.QuoteVerified {
			log.Printf("[TPM] Quote signature verified for %s - eligible for auto-approval", req.Hostname)
			tpmVerified = true
		} else {
			log.Printf("[TPM] Quote signature NOT verified for %s: %v", req.Hostname, result.Errors)
		}
	}

	// vSphere EK binding verification (anti-proxy attack for vSphere VMs)
	if tpmVerified && s.vsphereClient != nil && s.vsphereClient.EKBindingEnabled() {
		vmInfo, err := s.vsphereClient.LookupVMByIP(r.Context(), clientIP)
		if err != nil {
			log.Printf("[vSphere] EK lookup failed for %s: %v", clientIP, err)
		}

		if vmInfo != nil && vmInfo.HasVTPM {
			// VM is in vSphere and has a vTPM — verify EK binding
			if len(vmInfo.EKCertFingerprints) == 0 {
				if s.vsphereClient.RequireEK() {
					log.Printf("[vSphere] DENIED: VM %s has vTPM but no EK certs from vSphere (require_ek=true)", vmInfo.Name)
					tpmVerified = false
					machineReq.TPMAttestation.VerifyErrors = append(machineReq.TPMAttestation.VerifyErrors,
						"vSphere vTPM EK data unavailable and vsphere_require_ek is enabled")
				} else {
					log.Printf("[vSphere] WARNING: VM %s has vTPM but no EK certs from vSphere, skipping EK binding", vmInfo.Name)
				}
			} else if machineReq.TPMAttestation != nil && len(machineReq.TPMAttestation.EKCertificate) > 0 {
				// Compare agent's EK cert against vSphere-known fingerprints
				if tpm.MatchEKFingerprint(machineReq.TPMAttestation.EKCertificate, vmInfo.EKCertFingerprints) {
					log.Printf("[vSphere] EK binding verified for VM %s (%s) — vTPM identity confirmed", vmInfo.Name, clientIP)
				} else {
					log.Printf("[vSphere] DENIED: EK fingerprint mismatch for VM %s (%s) — possible proxy attack", vmInfo.Name, clientIP)
					tpmVerified = false
					machineReq.TPMAttestation.VerifyErrors = append(machineReq.TPMAttestation.VerifyErrors,
						"EK certificate does not match vSphere-registered vTPM")
				}
			} else if s.vsphereClient.RequireEK() {
				log.Printf("[vSphere] DENIED: Agent from %s did not provide EK certificate (require_ek=true)", clientIP)
				tpmVerified = false
				machineReq.TPMAttestation.VerifyErrors = append(machineReq.TPMAttestation.VerifyErrors,
					"agent did not provide EK certificate and vsphere_require_ek is enabled")
			} else {
				log.Printf("[vSphere] WARNING: Agent from %s did not provide EK certificate, skipping EK binding", clientIP)
			}
		} else if vmInfo == nil {
			log.Printf("[vSphere] IP %s not found in vCenter — not a vSphere VM, skipping EK binding", clientIP)
		}
	}

	// Debug: check if auto-approve would trigger
	if s.config.AutoApproveTPM {
		log.Printf("[TPM] AutoApproveTPM is enabled, tpmVerified=%v", tpmVerified)
	}

	// Check if already approved - use atomic ClaimToken to prevent race conditions
	if machineReq.Status == types.StatusApproved {
		// Atomically claim the token (prevents duplicate delivery if two polls arrive simultaneously)
		token := s.store.ClaimToken(machineReq.ID)
		if token != nil {
			log.Printf("[TOKEN] Delivering token for %s (id=%s, tokenID=%s, one-time delivery)", req.Hostname, machineReq.ID, token.TokenID)

			s.sendBootstrapResponse(w, http.StatusOK, &types.AutoBootstrapResponse{
				Status:  "approved",
				Message: "Machine approved - use this token",
				Type:    s.bootstrapResponseType(),
				Token:   token,
				Nonce:   s.generateAndStoreNonce(machineReq.ID),
			})
			return
		}

		// Token was already claimed by another request, or status changed - treat as pending
		log.Printf("[TOKEN] Token already claimed or missing for %s, treating as pending", req.Hostname)
		// Status was already reset by ClaimToken, fall through to pending handling
	}

	// Check if previously denied - reset to pending for new attempt
	if machineReq.Status == types.StatusDenied {
		log.Printf("Previously denied machine %s is retrying, resetting to pending", req.Hostname)
		s.store.ResetToPending(machineReq.ID)
		machineReq.Status = types.StatusPending
		isNew = true // Treat as new for messaging
	}

	// Check if previously expired - reset to pending for new attempt
	if machineReq.Status == types.StatusExpired {
		log.Printf("Previously expired machine %s is retrying, resetting to pending", req.Hostname)
		s.store.ResetToPending(machineReq.ID)
		machineReq.Status = types.StatusPending
		isNew = true // Treat as new for messaging
	}

	// Check if TPM is required but not provided
	if s.config.RequireTPM && !machineReq.HasTPM {
		s.sendBootstrapResponse(w, http.StatusOK, &types.AutoBootstrapResponse{
			Status:            "tpm_required",
			Message:           "TPM attestation is required",
			Nonce:             s.generateAndStoreNonce(machineReq.ID),
			RetryAfterSeconds: s.config.DefaultRetryAfter,
		})
		return
	}

	// Check if from trusted network and auto-approve is enabled
	if s.config.AutoApproveFromTrust && s.isFromTrustedNetwork(clientIP) {
		log.Printf("Auto-approving %s from trusted network %s", req.Hostname, clientIP)

		// Generate bootstrap token
		token, bootstrapType, err := s.generateTokenForAgent(machineReq)
		if err != nil {
			log.Printf("Failed to generate token for %s: %v", req.Hostname, err)
			s.sendBootstrapResponse(w, http.StatusInternalServerError, &types.AutoBootstrapResponse{
				Status:            "error",
				Message:           "Failed to generate token",
				RetryAfterSeconds: s.config.DefaultRetryAfter,
			})
			return
		}

		// Update store with approval
		if err := s.store.Approve(machineReq.ID, "auto-trust", token); err != nil {
			log.Printf("Failed to update approval: %v", err)
		}

		// Add audit entry for auto-approval
		s.store.AddAuditEntry(&types.AuditEntry{
			Timestamp:    machineReq.UpdatedAt,
			EventType:    types.AuditEventAutoApproval,
			RequestID:    machineReq.ID,
			Hostname:     machineReq.Hostname,
			MachineID:    machineReq.MachineID,
			IPAddresses:  machineReq.IPAddresses,
			MACAddresses: machineReq.MACAddresses,
			OS:           machineReq.OS,
			Arch:         machineReq.Arch,
			PerformedBy:  "auto-trust",
			Reason:       "Trusted network auto-approval",
			TokenID:      token.TokenID,
			ClientIP:     clientIP,
		})

		s.sendBootstrapResponse(w, http.StatusOK, &types.AutoBootstrapResponse{
			Status:  "approved",
			Message: "Machine approved (trusted network)",
			Type:    bootstrapType,
			Token:   token,
			Nonce:   s.generateAndStoreNonce(machineReq.ID),
		})
		return
	}

	// Check if TPM attestation is verified and auto-approve is enabled
	if s.config.AutoApproveTPM && tpmVerified {
		log.Printf("Auto-approving %s with verified TPM attestation", req.Hostname)

		// Generate bootstrap token
		token, bootstrapType, err := s.generateTokenForAgent(machineReq)
		if err != nil {
			log.Printf("Failed to generate token for %s: %v", req.Hostname, err)
			s.sendBootstrapResponse(w, http.StatusInternalServerError, &types.AutoBootstrapResponse{
				Status:            "error",
				Message:           "Failed to generate token",
				RetryAfterSeconds: s.config.DefaultRetryAfter,
			})
			return
		}

		// Update store with approval
		if err := s.store.Approve(machineReq.ID, "auto-tpm", token); err != nil {
			log.Printf("Failed to update approval: %v", err)
		}

		// Add audit entry for TPM auto-approval
		s.store.AddAuditEntry(&types.AuditEntry{
			Timestamp:    machineReq.UpdatedAt,
			EventType:    types.AuditEventAutoApproval,
			RequestID:    machineReq.ID,
			Hostname:     machineReq.Hostname,
			MachineID:    machineReq.MachineID,
			IPAddresses:  machineReq.IPAddresses,
			MACAddresses: machineReq.MACAddresses,
			OS:           machineReq.OS,
			Arch:         machineReq.Arch,
			PerformedBy:  "auto-tpm",
			Reason:       "TPM attestation verified",
			TokenID:      token.TokenID,
			ClientIP:     clientIP,
		})

		s.sendBootstrapResponse(w, http.StatusOK, &types.AutoBootstrapResponse{
			Status:  "approved",
			Message: "Machine approved (TPM attestation verified)",
			Type:    bootstrapType,
			Token:   token,
			Nonce:   s.generateAndStoreNonce(machineReq.ID),
		})
		return
	}

	// Check if reverse DNS matches hostname and auto-approve is enabled
	if s.config.AutoApproveDNS && matchesReverseDNS(clientIP, req.Hostname) {
		log.Printf("Auto-approving %s with verified reverse DNS from %s", req.Hostname, clientIP)

		// Generate bootstrap token
		token, bootstrapType, err := s.generateTokenForAgent(machineReq)
		if err != nil {
			log.Printf("Failed to generate token for %s: %v", req.Hostname, err)
			s.sendBootstrapResponse(w, http.StatusInternalServerError, &types.AutoBootstrapResponse{
				Status:            "error",
				Message:           "Failed to generate token",
				RetryAfterSeconds: s.config.DefaultRetryAfter,
			})
			return
		}

		// Update store with approval
		if err := s.store.Approve(machineReq.ID, "auto-dns", token); err != nil {
			log.Printf("Failed to update approval: %v", err)
		}

		// Add audit entry for DNS auto-approval
		s.store.AddAuditEntry(&types.AuditEntry{
			Timestamp:    machineReq.UpdatedAt,
			EventType:    types.AuditEventAutoApproval,
			RequestID:    machineReq.ID,
			Hostname:     machineReq.Hostname,
			MachineID:    machineReq.MachineID,
			IPAddresses:  machineReq.IPAddresses,
			MACAddresses: machineReq.MACAddresses,
			OS:           machineReq.OS,
			Arch:         machineReq.Arch,
			PerformedBy:  "auto-dns",
			Reason:       "Reverse DNS verification matched hostname",
			TokenID:      token.TokenID,
			ClientIP:     clientIP,
		})

		s.sendBootstrapResponse(w, http.StatusOK, &types.AutoBootstrapResponse{
			Status:  "approved",
			Message: "Machine approved (reverse DNS verified)",
			Type:    bootstrapType,
			Token:   token,
			Nonce:   s.generateAndStoreNonce(machineReq.ID),
		})
		return
	}

	// Request is pending - need operator approval
	queuePosition := s.store.GetQueuePosition(machineReq.ID)
	message := "Waiting for operator approval"
	if isNew {
		message = "Machine registered, waiting for operator approval"
		log.Printf("New machine registered: %s (ID: %s)", req.Hostname, machineReq.ID)

		// Broadcast new request event
		s.wsHub.Broadcast(EventNewRequest, RequestEventData{
			RequestID: machineReq.ID,
			Hostname:  machineReq.Hostname,
			ClientIP:  clientIP,
			OS:        machineReq.OS,
			Arch:      machineReq.Arch,
			Status:    string(machineReq.Status),
		})
	}

	s.sendBootstrapResponse(w, http.StatusOK, &types.AutoBootstrapResponse{
		Status:            "pending_approval",
		Message:           message,
		QueuePosition:     queuePosition,
		Nonce:             s.generateAndStoreNonce(machineReq.ID),
		RetryAfterSeconds: s.config.DefaultRetryAfter,
	})
}

// sendBootstrapResponse sends a JSON response to the agent
func (s *Server) sendBootstrapResponse(w http.ResponseWriter, status int, resp *types.AutoBootstrapResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// generateAndStoreNonce creates a new nonce and stores it with the request
func (s *Server) generateAndStoreNonce(requestID string) []byte {
	nonce := generateNonce()
	if err := s.store.UpdateNonce(requestID, nonce); err != nil {
		log.Printf("Failed to store nonce for request %s: %v", requestID, err)
	}
	return nonce
}

// handleListRequests returns bootstrap requests with optional pagination
// @Summary List bootstrap requests
// @Description Returns bootstrap requests, optionally filtered by status (supports pagination)
// @Tags Admin
// @Produce json
// @Param status query string false "Filter by status (pending, approved, denied)"
// @Param offset query int false "Offset for pagination (default 0)"
// @Param limit query int false "Limit for pagination (default 50, max 500, 0 for all)"
// @Success 200 {object} store.PaginatedRequests "Paginated list of bootstrap requests"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/requests [get]
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse pagination parameters
	params := store.DefaultPagination()
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			params.Offset = offset
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			if limit == 0 {
				params.Limit = 0 // No limit - return all
			} else if limit > 0 && limit <= 500 {
				params.Limit = limit
			} else if limit > 500 {
				params.Limit = 500 // Cap at 500
			}
		}
	}

	statusFilter := r.URL.Query().Get("status")

	var result *store.PaginatedRequests
	if statusFilter != "" {
		result = s.store.ListByStatusPaginated(types.RequestStatus(statusFilter), params)
	} else {
		result = s.store.ListPaginated(params)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRequest handles individual request operations
// @Summary Get or delete a bootstrap request
// @Description Get details of a specific request (GET) or delete it (DELETE)
// @Tags Admin
// @Produce json
// @Param id path string true "Request ID"
// @Success 200 {object} types.MachineRequest "Request details (GET)"
// @Success 200 {object} map[string]string "Deletion confirmation (DELETE)"
// @Failure 401 {string} string "Unauthorized"
// @Failure 404 {string} string "Request not found"
// @Security BasicAuth
// @Router /api/requests/{id} [get]
// @Router /api/requests/{id} [delete]
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/requests/")
	if id == "" {
		jsonError(w, "Request ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		req, err := s.store.Get(id)
		if err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(req)

	case http.MethodDelete:
		if err := s.store.Delete(id); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})

	default:
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleApprove approves a bootstrap request
// @Summary Approve a bootstrap request
// @Description Approves a pending bootstrap request and generates a token for the agent
// @Tags Admin
// @Accept json
// @Produce json
// @Param request body types.ApprovalRequest true "Approval details"
// @Success 200 {object} map[string]interface{} "Approval confirmation with token info"
// @Failure 400 {string} string "Invalid request or not pending"
// @Failure 401 {string} string "Unauthorized"
// @Failure 404 {string} string "Request not found"
// @Failure 500 {string} string "Token generation failed"
// @Security BasicAuth
// @Router /api/approve [post]
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.RequestID == "" {
		jsonError(w, "request_id is required", http.StatusBadRequest)
		return
	}

	// Get the machine request
	machineReq, err := s.store.Get(req.RequestID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	if machineReq.Status != types.StatusPending {
		jsonError(w, fmt.Sprintf("Request is not pending (status: %s)", machineReq.Status), http.StatusBadRequest)
		return
	}

	// Generate bootstrap token
	log.Printf("Generating token for %s (approved by %s)", machineReq.Hostname, req.ApprovedBy)
	token, bootstrapType, err := s.generateTokenForAgent(machineReq)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		jsonError(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	// Update the store
	approvedBy := req.ApprovedBy
	if approvedBy == "" {
		approvedBy = "operator"
	}
	if err := s.store.Approve(req.RequestID, approvedBy, token); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Approved %s, token expires: %s (type: %s)", machineReq.Hostname, token.ExpiresAt, bootstrapType)

	// Broadcast approval event
	s.wsHub.Broadcast(EventRequestApproved, RequestEventData{
		RequestID:  req.RequestID,
		Hostname:   machineReq.Hostname,
		Status:     "approved",
		ApprovedBy: approvedBy,
		TokenID:    token.TokenID,
		ExpiresAt:  token.ExpiresAt,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "approved",
		"type":       bootstrapType,
		"hostname":   machineReq.Hostname,
		"token_id":   token.TokenID,
		"expires_at": token.ExpiresAt,
	})
}

// handleGenerateToken generates a bootstrap token for manual local onboarding
// @Summary Generate bootstrap token for manual onboarding
// @Description Generates a bootstrap token that operators can use with the agent's local /bootstrap endpoint
// @Tags Admin
// @Accept json
// @Produce json
// @Param request body types.ApprovalRequest true "Token generation request"
// @Success 200 {object} map[string]interface{} "Token details including the actual token value"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 404 {string} string "Request not found"
// @Failure 500 {string} string "Token generation failed"
// @Security BasicAuth
// @Router /api/generate-token [post]
func (s *Server) handleGenerateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.ApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.RequestID == "" {
		jsonError(w, "request_id is required", http.StatusBadRequest)
		return
	}

	// Get the machine request
	machineReq, err := s.store.Get(req.RequestID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Generate bootstrap token
	generatedBy := req.ApprovedBy
	if generatedBy == "" {
		generatedBy = "operator"
	}
	log.Printf("Generating token for manual onboarding: %s (generated by %s)", machineReq.Hostname, generatedBy)

	token, _, err := s.generateTokenForAgent(machineReq)
	if err != nil {
		log.Printf("Failed to generate token: %v", err)
		jsonError(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Generated token for %s (manual onboarding), token expires: %s", machineReq.Hostname, token.ExpiresAt)

	// Broadcast token generated event
	s.wsHub.Broadcast(EventTokenGenerated, RequestEventData{
		RequestID: req.RequestID,
		Hostname:  machineReq.Hostname,
		TokenID:   token.TokenID,
		ExpiresAt: token.ExpiresAt,
	})

	// Return the full token for manual use - operator will use this with local /bootstrap
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "token_generated",
		"hostname":   machineReq.Hostname,
		"token":      token.Token, // The actual bootstrap token value
		"token_id":   token.TokenID,
		"expires_at": token.ExpiresAt,
		"role":       token.Role,
	})
}

// handleDeny denies a bootstrap request
// @Summary Deny a bootstrap request
// @Description Denies a pending bootstrap request with a reason
// @Tags Admin
// @Accept json
// @Produce json
// @Param request body types.DenialRequest true "Denial details with reason"
// @Success 200 {object} map[string]string "Denial confirmation"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 404 {string} string "Request not found"
// @Security BasicAuth
// @Router /api/deny [post]
func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.DenialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.RequestID == "" {
		jsonError(w, "request_id is required", http.StatusBadRequest)
		return
	}

	deniedBy := req.DeniedBy
	if deniedBy == "" {
		deniedBy = "operator"
	}

	reason := req.Reason
	if reason == "" {
		reason = "Denied by operator"
	}

	if err := s.store.Deny(req.RequestID, deniedBy, reason); err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	machineReq, _ := s.store.Get(req.RequestID)
	log.Printf("Denied %s: %s", machineReq.Hostname, reason)

	// Broadcast denial event
	s.wsHub.Broadcast(EventRequestDenied, RequestEventData{
		RequestID: req.RequestID,
		Hostname:  machineReq.Hostname,
		Status:    "denied",
		DeniedBy:  deniedBy,
		Reason:    reason,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "denied",
		"hostname": machineReq.Hostname,
		"reason":   reason,
	})
}

// handleStats returns dashboard statistics
// @Summary Get dashboard statistics
// @Description Returns statistics about bootstrap requests (total, pending, approved, denied)
// @Tags Admin
// @Produce json
// @Success 200 {object} types.DashboardStats "Dashboard statistics"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/stats [get]
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.store.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleVaultStatus returns Vault health status
// @Summary Get Vault health status
// @Description Returns the health status of the connected Vault server
// @Tags Admin
// @Produce json
// @Success 200 {object} vault.VaultHealthStatus "Vault health status"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/vault-status [get]
func (s *Server) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := s.getVaultHealthStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleDashboard serves the web dashboard
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}

	// Get data for dashboard
	stats := s.store.Stats()
	pending := s.store.ListByStatus(types.StatusPending)
	approved := s.store.ListByStatus(types.StatusApproved)
	denied := s.store.ListByStatus(types.StatusDenied)

	// Debug logging
	log.Printf("[DASHBOARD] Stats: total=%d, pending=%d, approved=%d, denied=%d",
		stats.TotalRequests, stats.PendingRequests, stats.ApprovedRequests, stats.DeniedRequests)
	log.Printf("[DASHBOARD] Pending list length: %d", len(pending))
	for i, p := range pending {
		log.Printf("[DASHBOARD] Pending[%d]: hostname=%s, status=%s, id=%s", i, p.Hostname, p.Status, p.ID)
	}

	data := struct {
		Stats    *types.DashboardStats
		Pending  []*types.MachineRequest
		Approved []*types.MachineRequest
		Denied   []*types.MachineRequest
		Version  string
	}{
		Stats:    stats,
		Pending:  pending,
		Approved: approved,
		Denied:   denied,
		Version:  version.Version,
	}

	// Parse and execute template with custom functions
	funcMap := template.FuncMap{
		"divf": func(a int64, b int64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
	}
	tmpl, err := template.New("dashboard").Funcs(funcMap).Parse(dashboardTemplate)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

// handleStatic serves static files
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// For now, inline CSS
	if strings.HasSuffix(r.URL.Path, ".css") {
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte(cssStyles))
		return
	}
	http.NotFound(w, r)
}

// handleFavicon serves the favicon
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(faviconSVG))
}

// faviconSVG is a simple SVG favicon - a stylized "B" for Bootstrap
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#16213e"/>
    </linearGradient>
  </defs>
  <rect width="32" height="32" rx="6" fill="url(#bg)"/>
  <text x="16" y="23" font-family="Arial, sans-serif" font-size="20" font-weight="bold" fill="white" text-anchor="middle">B</text>
  <circle cx="26" cy="6" r="4" fill="#27ae60"/>
</svg>`

// Dashboard HTML template
const dashboardTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Bootstrap Server Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/svg+xml" href="/favicon.ico">
    <link rel="stylesheet" href="/static/style.css">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 24px; }
        .nav-links { display: flex; gap: 15px; }
        .nav-links a { color: white; text-decoration: none; padding: 8px 16px; background: rgba(255,255,255,0.1); border-radius: 4px; }
        .nav-links a:hover { background: rgba(255,255,255,0.2); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-card .number { font-size: 36px; font-weight: bold; color: #1a1a2e; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .stat-card.pending .number { color: #f39c12; }
        .stat-card.approved .number { color: #27ae60; }
        .stat-card.denied .number { color: #e74c3c; }
        .section { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section-header { padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .section-header h2 { font-size: 18px; color: #333; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; }
        .badge-pending { background: #fff3cd; color: #856404; }
        .badge-approved { background: #d4edda; color: #155724; }
        .badge-denied { background: #f8d7da; color: #721c24; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #333; }
        tr:hover { background: #f8f9fa; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; transition: background 0.2s; }
        .btn-approve { background: #27ae60; color: white; }
        .btn-approve:hover { background: #219a52; }
        .btn-deny { background: #e74c3c; color: white; margin-left: 8px; }
        .btn-deny:hover { background: #c0392b; }
        .btn-token { background: #9b59b6; color: white; margin-left: 8px; }
        .btn-token:hover { background: #8e44ad; }
        .btn-delete { background: #95a5a6; color: white; margin-left: 8px; }
        .btn-delete:hover { background: #7f8c8d; }
        /* Modal styles */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); }
        .modal-content { background: white; margin: 10% auto; padding: 30px; border-radius: 8px; max-width: 600px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h3 { font-size: 20px; color: #333; }
        .modal-close { background: none; border: none; font-size: 28px; cursor: pointer; color: #999; }
        .modal-close:hover { color: #333; }
        .token-box { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; font-family: monospace; font-size: 14px; word-break: break-all; margin: 15px 0; }
        .token-info { font-size: 13px; color: #666; margin-top: 10px; }
        .copy-btn { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-top: 15px; }
        .copy-btn:hover { background: #2980b9; }
        .copy-btn.copied { background: #27ae60; }
        .empty { padding: 40px; text-align: center; color: #999; }
        .machine-info { font-size: 12px; color: #666; }
        .ip-list { font-family: monospace; font-size: 11px; }
        .tpm-badge { background: #3498db; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px; cursor: pointer; transition: background 0.2s; }
        .tpm-badge:hover { background: #2980b9; }
        .tpm-verified { background: #27ae60; }
        .tpm-unverified { background: #e67e22; }
        .tpm-info-row { display: flex; margin-bottom: 8px; }
        /* Vault status indicator */
        .vault-status { display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: rgba(255,255,255,0.1); border-radius: 4px; font-size: 13px; }
        .vault-status-dot { width: 10px; height: 10px; border-radius: 50%; }
        .vault-status-dot.healthy { background: #27ae60; box-shadow: 0 0 6px #27ae60; }
        .vault-status-dot.unhealthy { background: #e74c3c; box-shadow: 0 0 6px #e74c3c; }
        .vault-status-dot.unknown { background: #f39c12; box-shadow: 0 0 6px #f39c12; }
        .vault-status-text { color: rgba(255,255,255,0.9); }
        .vault-status-details { font-size: 11px; color: rgba(255,255,255,0.6); }
        .tpm-info-label { font-weight: bold; width: 120px; color: #555; }
        .tpm-info-value { font-family: monospace; font-size: 12px; word-break: break-all; flex: 1; }
        .tpm-info-section { margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee; }
        .tpm-info-section h4 { margin: 0 0 10px 0; color: #333; font-size: 14px; }
        .pcr-table { width: 100%; font-size: 11px; border-collapse: collapse; }
        .pcr-table th, .pcr-table td { padding: 4px 8px; text-align: left; border-bottom: 1px solid #eee; }
        .pcr-table th { background: #f8f9fa; }
        .pcr-value { font-family: monospace; font-size: 10px; }
        .refresh-btn { background: #3498db; color: white; }
        .refresh-btn:hover { background: #2980b9; }
        .actions { white-space: nowrap; }
        .version-badge { font-size: 12px; font-weight: normal; background: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 4px; margin-left: 10px; vertical-align: middle; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div style="display: flex; align-items: center; gap: 20px;">
                <h1>Bootstrap Server Dashboard <span class="version-badge">{{.Version}}</span></h1>
                <div class="vault-status" id="vault-status" title="Vault Status">
                    <div class="vault-status-dot unknown" id="vault-status-dot"></div>
                    <div>
                        <div class="vault-status-text" id="vault-status-text">Vault: Checking...</div>
                        <div class="vault-status-details" id="vault-status-details"></div>
                    </div>
                </div>
            </div>
            <nav class="nav-links">
                <a href="/">Bootstrap Requests</a>
                <a href="/system">Registered Agents</a>
                <a href="/alerts">Alerts</a>
                <a href="/manual-bootstrap">Manual Bootstrap</a>
                <a href="/audit">Audit Log</a>
            </nav>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{{.Stats.TotalRequests}}</div>
                <div class="label">Total Requests</div>
            </div>
            <div class="stat-card pending">
                <div class="number">{{.Stats.PendingRequests}}</div>
                <div class="label">Pending</div>
            </div>
            <div class="stat-card approved">
                <div class="number">{{.Stats.ApprovedRequests}}</div>
                <div class="label">Approved</div>
            </div>
            <div class="stat-card denied">
                <div class="number">{{.Stats.DeniedRequests}}</div>
                <div class="label">Denied</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Pending Requests <span class="badge badge-pending">{{len .Pending}}</span></h2>
                <button class="btn refresh-btn" onclick="location.reload()">Refresh</button>
            </div>
            {{if .Pending}}
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>OS / Arch</th>
                        <th>IP Addresses</th>
                        <th>Uptime</th>
                        <th>TPM</th>
                        <th>First Seen</th>
                        <th>Requests</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {{range .Pending}}
                <tr>
                    <td><strong>{{.Hostname}}</strong><br><span class="machine-info">{{.ClientIP}}</span></td>
                    <td>{{.OS}} / {{.Arch}}<br><span class="machine-info">{{.OSVersion}}</span></td>
                    <td class="ip-list">{{range .IPAddresses}}{{.}}<br>{{end}}</td>
                    <td>{{printf "%.1f" (divf .UptimeSeconds 3600)}}h</td>
                    <td>{{if .HasTPM}}<span class="tpm-badge{{if .TPMAttestation}}{{if .TPMAttestation.Verified}} tpm-verified{{else}} tpm-unverified{{end}}{{end}}" onclick="showTPMInfo('{{.ID}}', '{{.Hostname}}')" title="Click for TPM details">TPM{{if .TPMAttestation}}{{if .TPMAttestation.Verified}} ✓{{end}}{{end}}</span>{{else}}-{{end}}</td>
                    <td>{{.CreatedAt.Format "Jan 02 15:04"}}</td>
                    <td>{{.RequestCount}}</td>
                    <td class="actions">
                        <button class="btn btn-approve" onclick="approve('{{.ID}}')">Approve</button>
                        <button class="btn btn-token" onclick="getToken('{{.ID}}', '{{.Hostname}}')">Get Token</button>
                        <button class="btn btn-deny" onclick="deny('{{.ID}}')">Deny</button>
                    </td>
                </tr>
                {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="empty">No pending requests</div>
            {{end}}
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Recently Approved <span class="badge badge-approved">{{len .Approved}}</span></h2>
            </div>
            {{if .Approved}}
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>Token ID</th>
                        <th>Expires</th>
                        <th>Approved By</th>
                        <th>Approved At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {{range .Approved}}
                <tr>
                    <td><strong>{{.Hostname}}</strong></td>
                    <td class="machine-info">{{if .Token}}{{.Token.TokenID}}{{end}}</td>
                    <td class="machine-info">{{if .Token}}{{.Token.ExpiresAt}}{{end}}</td>
                    <td>{{.ApprovedBy}}</td>
                    <td>{{if .ApprovedAt}}{{.ApprovedAt.Format "Jan 02 15:04"}}{{end}}</td>
                    <td class="actions">
                        <button class="btn btn-delete" onclick="deleteReq('{{.ID}}')">Remove</button>
                    </td>
                </tr>
                {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="empty">No approved requests</div>
            {{end}}
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Denied <span class="badge badge-denied">{{len .Denied}}</span></h2>
            </div>
            {{if .Denied}}
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>Reason</th>
                        <th>Denied By</th>
                        <th>Denied At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                {{range .Denied}}
                <tr>
                    <td><strong>{{.Hostname}}</strong></td>
                    <td>{{.DenialReason}}</td>
                    <td>{{.DeniedBy}}</td>
                    <td>{{if .DeniedAt}}{{.DeniedAt.Format "Jan 02 15:04"}}{{end}}</td>
                    <td class="actions">
                        <button class="btn btn-delete" onclick="deleteReq('{{.ID}}')">Remove</button>
                    </td>
                </tr>
                {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="empty">No denied requests</div>
            {{end}}
        </div>
    </div>

    <!-- Token Modal -->
    <div id="tokenModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Bootstrap Token for <span id="modalHostname"></span></h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <p>Use this token with the agent's local bootstrap endpoint:</p>
            <div class="token-box" id="tokenValue"></div>
            <div class="token-info">
                <strong>Token ID:</strong> <span id="tokenId"></span><br>
                <strong>Expires:</strong> <span id="tokenExpires"></span><br>
                <strong>Role:</strong> <span id="tokenRole"></span>
            </div>
            <p style="margin-top: 15px; font-size: 13px; color: #666;">
                <strong>Usage:</strong> POST this token to the agent's local endpoint:<br>
                <code style="background: #f1f1f1; padding: 2px 6px; border-radius: 3px;">curl -X POST -d '{"token":"&lt;token&gt;"}' http://localhost:4001/bootstrap</code>
            </p>
            <button class="copy-btn" onclick="copyToken()">Copy Token</button>
        </div>
    </div>

    <!-- TPM Info Modal -->
    <div id="tpmModal" class="modal">
        <div class="modal-content" style="max-width: 700px;">
            <div class="modal-header">
                <h3>TPM Attestation - <span id="tpmModalHostname"></span></h3>
                <button class="modal-close" onclick="closeTPMModal()">&times;</button>
            </div>
            <div id="tpmInfoContent">
                <div class="tpm-info-row">
                    <span class="tpm-info-label">Status:</span>
                    <span class="tpm-info-value" id="tpmStatus"></span>
                </div>
                <div class="tpm-info-row">
                    <span class="tpm-info-label">Quote Size:</span>
                    <span class="tpm-info-value" id="tpmQuoteSize"></span>
                </div>
                <div class="tpm-info-row">
                    <span class="tpm-info-label">Signature Size:</span>
                    <span class="tpm-info-value" id="tpmSigSize"></span>
                </div>
                <div class="tpm-info-row">
                    <span class="tpm-info-label">AK Public:</span>
                    <span class="tpm-info-value" id="tpmAKPublic"></span>
                </div>
                <div class="tpm-info-row">
                    <span class="tpm-info-label">EK Certificate:</span>
                    <span class="tpm-info-value" id="tpmEKCert"></span>
                </div>
                <div class="tpm-info-section">
                    <h4>PCR Digest</h4>
                    <div class="tpm-info-value" id="tpmPCRDigest" style="background: #f8f9fa; padding: 8px; border-radius: 4px;"></div>
                </div>
                <div class="tpm-info-section" id="tpmErrorsSection" style="display: none;">
                    <h4>Verification Errors</h4>
                    <ul id="tpmErrors" style="color: #e74c3c; margin: 0; padding-left: 20px;"></ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Vault status polling
        function updateVaultStatus() {
            fetch('/api/vault-status')
                .then(r => r.json())
                .then(status => {
                    const dot = document.getElementById('vault-status-dot');
                    const text = document.getElementById('vault-status-text');
                    const details = document.getElementById('vault-status-details');

                    dot.className = 'vault-status-dot ' + (status.healthy ? 'healthy' : 'unhealthy');

                    if (status.healthy) {
                        text.textContent = 'Vault: Connected';
                        let detailText = status.version || '';
                        if (status.standby) detailText += ' (standby)';
                        if (status.response_time_ms) detailText += ' · ' + status.response_time_ms + 'ms';
                        details.textContent = detailText;
                    } else {
                        text.textContent = 'Vault: ' + (status.error || 'Unhealthy');
                        details.textContent = status.sealed ? 'Sealed' : (status.initialized ? '' : 'Not initialized');
                    }
                })
                .catch(err => {
                    document.getElementById('vault-status-dot').className = 'vault-status-dot unhealthy';
                    document.getElementById('vault-status-text').textContent = 'Vault: Error';
                    document.getElementById('vault-status-details').textContent = err.message || 'Connection failed';
                });
        }

        // Initial check and periodic polling (every 20 seconds)
        updateVaultStatus();
        setInterval(updateVaultStatus, 20000);

        function approve(id) {
            if (!confirm('Approve this machine?')) return;
            fetch('/api/approve', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({request_id: id, approved_by: 'operator'})
            }).then(r => r.json()).then(data => {
                if (data.status === 'approved') {
                    alert('Machine approved: ' + data.hostname + ' (token expires: ' + data.expires_at + ')');
                    location.reload();
                } else {
                    alert('Error: ' + JSON.stringify(data));
                }
            }).catch(err => alert('Error: ' + err));
        }

        function deny(id) {
            const reason = prompt('Reason for denial:');
            if (!reason) return;
            fetch('/api/deny', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({request_id: id, denied_by: 'operator', reason: reason})
            }).then(r => r.json()).then(data => {
                if (data.status === 'denied') {
                    alert('Machine denied');
                    location.reload();
                } else {
                    alert('Error: ' + JSON.stringify(data));
                }
            }).catch(err => alert('Error: ' + err));
        }

        function deleteReq(id) {
            if (!confirm('Remove this request?')) return;
            fetch('/api/requests/' + id, {method: 'DELETE'})
                .then(r => r.json())
                .then(() => location.reload())
                .catch(err => alert('Error: ' + err));
        }

        function showTPMInfo(id, hostname) {
            document.getElementById('tpmModalHostname').textContent = hostname;
            // Fetch request details to get TPM info
            fetch('/api/requests/' + id)
                .then(r => r.json())
                .then(data => {
                    if (data.tpm_attestation) {
                        const tpm = data.tpm_attestation;
                        document.getElementById('tpmStatus').innerHTML = tpm.verified
                            ? '<span style="color: #27ae60;">✓ Verified</span>'
                            : '<span style="color: #e67e22;">⚠ Not Verified</span>';
                        document.getElementById('tpmQuoteSize').textContent = tpm.quote ? tpm.quote.length + ' bytes (base64)' : 'N/A';
                        document.getElementById('tpmSigSize').textContent = tpm.signature ? tpm.signature.length + ' bytes (base64)' : 'N/A';
                        document.getElementById('tpmAKPublic').textContent = tpm.ak_public ? tpm.ak_public.substring(0, 64) + '...' : 'N/A';
                        document.getElementById('tpmEKCert').textContent = tpm.ek_certificate ? 'Present (' + tpm.ek_certificate.length + ' bytes)' : 'Not provided';
                        document.getElementById('tpmPCRDigest').textContent = tpm.pcr_digest || 'N/A';

                        // Show errors if any
                        const errorsSection = document.getElementById('tpmErrorsSection');
                        const errorsList = document.getElementById('tpmErrors');
                        if (tpm.verify_errors && tpm.verify_errors.length > 0) {
                            errorsList.innerHTML = tpm.verify_errors.map(e => '<li>' + e + '</li>').join('');
                            errorsSection.style.display = 'block';
                        } else {
                            errorsSection.style.display = 'none';
                        }
                    } else {
                        document.getElementById('tpmStatus').textContent = 'No TPM data available';
                        document.getElementById('tpmQuoteSize').textContent = '-';
                        document.getElementById('tpmSigSize').textContent = '-';
                        document.getElementById('tpmAKPublic').textContent = '-';
                        document.getElementById('tpmEKCert').textContent = '-';
                        document.getElementById('tpmPCRDigest').textContent = '-';
                        document.getElementById('tpmErrorsSection').style.display = 'none';
                    }
                    document.getElementById('tpmModal').style.display = 'block';
                })
                .catch(err => alert('Error fetching TPM info: ' + err));
        }

        function closeTPMModal() {
            document.getElementById('tpmModal').style.display = 'none';
        }

        let currentToken = '';

        function getToken(id, hostname) {
            fetch('/api/generate-token', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({request_id: id, approved_by: 'operator'})
            }).then(r => r.json()).then(data => {
                if (data.status === 'token_generated') {
                    currentToken = data.token;
                    document.getElementById('modalHostname').textContent = data.hostname;
                    document.getElementById('tokenValue').textContent = data.token;
                    document.getElementById('tokenId').textContent = data.token_id;
                    document.getElementById('tokenExpires').textContent = data.expires_at;
                    document.getElementById('tokenRole').textContent = data.role || 'default';
                    document.getElementById('tokenModal').style.display = 'block';
                } else {
                    alert('Error: ' + JSON.stringify(data));
                }
            }).catch(err => alert('Error: ' + err));
        }

        function closeModal() {
            document.getElementById('tokenModal').style.display = 'none';
            currentToken = '';
        }

        function copyToken() {
            navigator.clipboard.writeText(currentToken).then(() => {
                const btn = document.querySelector('.copy-btn');
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy Token';
                    btn.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = currentToken;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                const btn = document.querySelector('.copy-btn');
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy Token';
                    btn.classList.remove('copied');
                }, 2000);
            });
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const tokenModal = document.getElementById('tokenModal');
            const tpmModal = document.getElementById('tpmModal');
            if (event.target === tokenModal) {
                closeModal();
            }
            if (event.target === tpmModal) {
                closeTPMModal();
            }
        }

        // WebSocket connection for real-time updates
        let ws = null;
        let wsReconnectTimer = null;
        const wsReconnectDelay = 3000;

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws';

            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                console.log('[WebSocket] Connected');
                clearTimeout(wsReconnectTimer);
                // Show connection status
                updateConnectionStatus(true);
            };

            ws.onclose = function() {
                console.log('[WebSocket] Disconnected, reconnecting...');
                updateConnectionStatus(false);
                wsReconnectTimer = setTimeout(connectWebSocket, wsReconnectDelay);
            };

            ws.onerror = function(err) {
                console.error('[WebSocket] Error:', err);
            };

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                handleWebSocketEvent(data);
            };
        }

        function updateConnectionStatus(connected) {
            const indicator = document.getElementById('ws-status');
            if (indicator) {
                indicator.style.background = connected ? '#27ae60' : '#e74c3c';
                indicator.title = connected ? 'Real-time updates active' : 'Reconnecting...';
            }
        }

        function handleWebSocketEvent(event) {
            console.log('[WebSocket] Event:', event.type, event.data);

            switch(event.type) {
                case 'new_request':
                    showNotification('New bootstrap request from ' + event.data.hostname, 'info');
                    // Reload to show new request (could be optimized to add row dynamically)
                    location.reload();
                    break;

                case 'request_approved':
                    showNotification('Request approved: ' + event.data.hostname, 'success');
                    location.reload();
                    break;

                case 'request_denied':
                    showNotification('Request denied: ' + event.data.hostname, 'warning');
                    location.reload();
                    break;

                case 'token_generated':
                    showNotification('Token generated for ' + event.data.hostname, 'info');
                    break;

                case 'initial_state':
                    console.log('[WebSocket] Initial state received');
                    break;
            }
        }

        function showNotification(message, type) {
            // Create notification element
            const notification = document.createElement('div');
            notification.className = 'notification notification-' + type;
            notification.textContent = message;
            notification.style.cssText = 'position:fixed;top:20px;right:20px;padding:15px 20px;border-radius:4px;color:white;z-index:1000;animation:fadeIn 0.3s;';

            switch(type) {
                case 'success': notification.style.background = '#27ae60'; break;
                case 'warning': notification.style.background = '#f39c12'; break;
                case 'error': notification.style.background = '#e74c3c'; break;
                default: notification.style.background = '#3498db';
            }

            document.body.appendChild(notification);

            // Remove after 5 seconds
            setTimeout(() => {
                notification.style.opacity = '0';
                setTimeout(() => notification.remove(), 300);
            }, 5000);
        }

        // Connect to WebSocket on page load
        connectWebSocket();

        // Fallback: refresh every 60 seconds if WebSocket fails
        setTimeout(() => {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                location.reload();
            }
        }, 60000);
    </script>
</body>
</html>`

// CSS styles
const cssStyles = `
/* Additional styles can go here */
`

// --- Agent Registration Handlers ---

// handleRegistration receives registration/heartbeat from agents
// @Summary Register agent heartbeat
// @Description Agents call this endpoint to register and send periodic heartbeats with status information
// @Tags System
// @Accept json
// @Produce json
// @Param registration body types.AgentRegistration true "Agent registration/heartbeat data"
// @Success 200 {object} map[string]string "Registration accepted"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Client certificate required (when mTLS enabled)"
// @Router /registration [post]
func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check client certificate if mTLS is required
	var certVerified bool
	var certIdentity string

	if s.config.RegistrationRequireMTLS {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			log.Printf("Registration rejected: no client certificate provided")
			jsonError(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		// Get the client certificate
		clientCert := r.TLS.PeerCertificates[0]

		// Verify the certificate against our CA pool
		if s.registrationCAPool != nil {
			opts := x509.VerifyOptions{
				Roots:     s.registrationCAPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			// Build intermediate pool from the certificate chain
			if len(r.TLS.PeerCertificates) > 1 {
				opts.Intermediates = x509.NewCertPool()
				for _, cert := range r.TLS.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
			}

			if _, err := clientCert.Verify(opts); err != nil {
				log.Printf("Registration rejected: certificate verification failed: %v", err)
				jsonError(w, "Invalid client certificate", http.StatusUnauthorized)
				return
			}
		}

		certVerified = true

		// Extract identity from certificate
		// Check for SPIFFE ID in SAN URIs first, fall back to CN
		for _, uri := range clientCert.URIs {
			if uri.Scheme == "spiffe" {
				certIdentity = uri.String()
				break
			}
		}
		if certIdentity == "" {
			certIdentity = clientCert.Subject.CommonName
		}

		log.Printf("Registration mTLS verified: identity=%s", certIdentity)
	} else if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// mTLS not required, but client sent a cert - still record it
		clientCert := r.TLS.PeerCertificates[0]
		certVerified = true
		for _, uri := range clientCert.URIs {
			if uri.Scheme == "spiffe" {
				certIdentity = uri.String()
				break
			}
		}
		if certIdentity == "" {
			certIdentity = clientCert.Subject.CommonName
		}
	}

	var reg types.AgentRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if reg.AgentID == "" {
		jsonError(w, "agent_id is required", http.StatusBadRequest)
		return
	}

	// Set server-side fields
	reg.ClientIP = getClientIP(r)
	reg.CertVerified = certVerified
	reg.CertIdentity = certIdentity

	// PoW verification (advisory mode - we still accept registration but log/alert on failures)
	log.Printf("[PoW] Registration from %s: SecureHeartbeat=%v, powVerifier=%v", reg.AgentID, reg.SecureHeartbeat != nil, s.powVerifier != nil)
	if reg.SecureHeartbeat != nil && s.powVerifier != nil {
		verification := s.powVerifier.Verify(reg.SecureHeartbeat)
		reg.PoWVerification = verification

		// Determine status
		if verification.Valid && len(verification.Warnings) == 0 {
			reg.PoWStatus = "ok"
		} else if verification.Valid && len(verification.Warnings) > 0 {
			reg.PoWStatus = "warning"
		} else {
			reg.PoWStatus = "failed"
		}

		// Broadcast PoW event based on status
		powEventData := PoWEventData{
			AgentID:          reg.AgentID,
			Hostname:         reg.Hostname,
			ClientIP:         reg.ClientIP,
			Status:           reg.PoWStatus,
			ChainValid:       verification.ChainValid,
			WorkValid:        verification.WorkValid,
			MetricsValid:     verification.MetricsValid,
			WitnessCount:     verification.WitnessCount,
			WitnessThreshold: verification.WitnessThreshold,
			Errors:           verification.Errors,
			Warnings:         verification.Warnings,
			Sequence:         reg.SecureHeartbeat.Sequence,
		}

		switch reg.PoWStatus {
		case "warning":
			log.Printf("[PoW] Warning for %s: %v", reg.AgentID, verification.Warnings)
			s.wsHub.Broadcast(EventPoWWarning, powEventData)
		case "failed":
			log.Printf("[PoW] FAILED for %s: %v", reg.AgentID, verification.Errors)
			s.wsHub.Broadcast(EventPoWFailed, powEventData)
		default:
			// Only broadcast success events if there was actually a heartbeat
			if reg.SecureHeartbeat.Sequence > 0 {
				s.wsHub.Broadcast(EventPoWVerified, powEventData)
			}
		}
	} else {
		reg.PoWStatus = "disabled"
	}

	// Store the registration
	if err := s.store.UpsertRegistration(&reg); err != nil {
		log.Printf("Failed to store registration for %s: %v", reg.AgentID, err)
		jsonError(w, "Failed to store registration", http.StatusInternalServerError)
		return
	}

	// Alert service: check for version changes and resolve stale alerts
	if s.alertService != nil {
		s.alertService.CheckVersionChange(&reg)
		s.alertService.ResolveStaleAlertIfActive(reg.AgentID)
	}

	if certVerified {
		log.Printf("Registration from %s (%s) at %s [mTLS: %s]", reg.AgentID, reg.Hostname, reg.ClientIP, certIdentity)
	} else {
		log.Printf("Registration from %s (%s) at %s [no mTLS]", reg.AgentID, reg.Hostname, reg.ClientIP)
	}

	// Broadcast agent registration event
	s.wsHub.Broadcast(EventAgentRegistered, AgentEventData{
		AgentID:  reg.AgentID,
		Hostname: reg.Hostname,
		ClientIP: reg.ClientIP,
		OS:       reg.OS,
		Arch:     reg.Arch,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleListRegistrations returns agent registrations with optional pagination
// @Summary List registered agents
// @Description Returns registered agents with their status information (supports pagination)
// @Tags System
// @Produce json
// @Param offset query int false "Offset for pagination (default 0)"
// @Param limit query int false "Limit for pagination (default 50, max 500, 0 for all)"
// @Success 200 {object} store.PaginatedRegistrations "Paginated list of registered agents"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/systems [get]
func (s *Server) handleListRegistrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse pagination parameters
	params := store.DefaultPagination()
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			params.Offset = offset
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			if limit == 0 {
				params.Limit = 0 // No limit - return all
			} else if limit > 0 && limit <= 500 {
				params.Limit = limit
			} else if limit > 500 {
				params.Limit = 500 // Cap at 500
			}
		}
	}

	result := s.store.ListRegistrationsPaginated(params)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleRegistrationDelete handles DELETE requests for individual registrations
// @Summary Delete a registration
// @Description Delete an agent registration by ID
// @Tags System
// @Param id path string true "Agent ID"
// @Success 200 {object} map[string]string "Deletion status"
// @Failure 404 {string} string "Registration not found"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/systems/{id} [delete]
func (s *Server) handleRegistrationDelete(w http.ResponseWriter, r *http.Request) {
	// Extract agent ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/systems/")
	agentID := strings.TrimSuffix(path, "/")

	if agentID == "" {
		jsonError(w, "Agent ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		// Get registration info for logging
		reg, err := s.store.GetRegistration(agentID)
		if err != nil {
			jsonError(w, "Registration not found: "+agentID, http.StatusNotFound)
			return
		}

		// Delete the registration
		if err := s.store.DeleteRegistration(agentID); err != nil {
			jsonError(w, "Failed to delete registration: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Also delete any alerts for this agent
		alerts := s.store.ListAlerts()
		for _, alert := range alerts {
			if alert.AgentID == agentID {
				s.store.DeleteAlert(alert.ID)
			}
		}

		log.Printf("[Systems] Deleted registration for %s (%s, version %s)", reg.Hostname, agentID, reg.AgentVersion)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "deleted",
			"agent_id": agentID,
			"hostname": reg.Hostname,
		})

	case http.MethodGet:
		// Get single registration
		reg, err := s.store.GetRegistration(agentID)
		if err != nil {
			jsonError(w, "Registration not found: "+agentID, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reg)

	default:
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSystemStats returns statistics about registered agents
// @Summary Get system statistics
// @Description Returns statistics about registered agents (total, active, CA ready)
// @Tags System
// @Produce json
// @Success 200 {object} types.SystemStats "System statistics"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/system-stats [get]
func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.store.SystemStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleSystemDashboard serves the system dashboard
// GET /system
func (s *Server) handleSystemDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/system" && r.URL.Path != "/system/" {
		http.NotFound(w, r)
		return
	}

	// Parse pagination parameters
	params := store.PaginationParams{Offset: 0, Limit: 50}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			params.Offset = offset
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 200 {
			params.Limit = limit
		}
	}

	stats := s.store.SystemStats()
	paginatedRegs := s.store.ListRegistrationsPaginated(params)

	// Calculate pagination info
	totalPages := (paginatedRegs.Total + params.Limit - 1) / params.Limit
	currentPage := (params.Offset / params.Limit) + 1
	hasNext := params.Offset+params.Limit < paginatedRegs.Total
	hasPrev := params.Offset > 0

	data := struct {
		Stats         *types.SystemStats
		Registrations []*types.AgentRegistration
		Version       string
		Pagination    struct {
			Total       int
			Offset      int
			Limit       int
			CurrentPage int
			TotalPages  int
			HasNext     bool
			HasPrev     bool
			NextOffset  int
			PrevOffset  int
		}
	}{
		Stats:         stats,
		Registrations: paginatedRegs.Data,
		Version:       version.Version,
	}
	data.Pagination.Total = paginatedRegs.Total
	data.Pagination.Offset = params.Offset
	data.Pagination.Limit = params.Limit
	data.Pagination.CurrentPage = currentPage
	data.Pagination.TotalPages = totalPages
	data.Pagination.HasNext = hasNext
	data.Pagination.HasPrev = hasPrev
	data.Pagination.NextOffset = params.Offset + params.Limit
	data.Pagination.PrevOffset = params.Offset - params.Limit
	if data.Pagination.PrevOffset < 0 {
		data.Pagination.PrevOffset = 0
	}

	funcMap := template.FuncMap{
		"divf": func(a int64, b int64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
	}
	tmpl, err := template.New("system").Funcs(funcMap).Parse(systemDashboardTemplate)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

// System dashboard HTML template
const systemDashboardTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>System Dashboard - Bootstrap Server</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/svg+xml" href="/favicon.ico">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 24px; }
        .nav-links { display: flex; gap: 15px; }
        .nav-links a { color: white; text-decoration: none; padding: 8px 16px; background: rgba(255,255,255,0.1); border-radius: 4px; }
        .nav-links a:hover { background: rgba(255,255,255,0.2); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-card .number { font-size: 36px; font-weight: bold; color: #1a1a2e; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .stat-card.active .number { color: #27ae60; }
        .stat-card.ca-ready .number { color: #3498db; }
        .section { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; overflow: hidden; }
        .section-header { padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
        .section-header h2 { font-size: 18px; color: #333; }
        .header-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        table { width: 100%; border-collapse: collapse; table-layout: fixed; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; overflow: hidden; text-overflow: ellipsis; }
        th:nth-child(1), td:nth-child(1) { width: 10%; } /* Agent ID */
        th:nth-child(2), td:nth-child(2) { width: 10%; } /* Hostname */
        th:nth-child(3), td:nth-child(3) { width: 8%; } /* OS/Arch */
        th:nth-child(4), td:nth-child(4) { width: 6%; }  /* Version */
        th:nth-child(5), td:nth-child(5) { width: 12%; } /* IP Addresses */
        th:nth-child(6), td:nth-child(6) { width: 10%; } /* CA Status */
        th:nth-child(7), td:nth-child(7) { width: 9%; } /* PoW Status */
        th:nth-child(8), td:nth-child(8) { width: 6%; }  /* Uptime */
        th:nth-child(9), td:nth-child(9) { width: 11%; } /* Last Seen */
        th:nth-child(10), td:nth-child(10) { width: 8%; }  /* Heartbeats */
        th:nth-child(11), td:nth-child(11) { width: 10%; }  /* Actions */
        th { background: #f8f9fa; font-weight: 600; color: #333; position: sticky; top: 0; }
        tr:hover { background: #f8f9fa; }
        tr.hidden { display: none; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; }
        .badge-ready { background: #d4edda; color: #155724; }
        .badge-not-ready { background: #f8d7da; color: #721c24; }
        .badge-connected { background: #d1ecf1; color: #0c5460; }
        .badge-disconnected { background: #fff3cd; color: #856404; }
        .badge-active { background: #d4edda; color: #155724; }
        .badge-stale { background: #e2e3e5; color: #383d41; }
        .badge-pow-ok { background: #d4edda; color: #155724; }
        .badge-pow-warning { background: #fff3cd; color: #856404; }
        .badge-pow-failed { background: #f8d7da; color: #721c24; }
        .badge-pow-disabled { background: #e2e3e5; color: #383d41; }
        .pow-info { font-size: 11px; margin-top: 3px; color: #666; }
        .pow-info .error { color: #e74c3c; }
        .pow-info .warning { color: #f39c12; }
        .mono { font-family: 'SF Mono', Monaco, monospace; font-size: 12px; }
        .ip-list { font-size: 11px; white-space: nowrap; }
        .ca-info { font-size: 11px; }
        .ca-info .expires { color: #e74c3c; }
        .ca-info .renews { color: #27ae60; }
        .empty { padding: 40px; text-align: center; color: #999; }
        .no-results { padding: 40px; text-align: center; color: #999; display: none; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn-refresh { background: #3498db; color: white; }
        .btn-refresh:hover { background: #2980b9; }
        .btn-clear { background: #95a5a6; color: white; font-size: 12px; padding: 6px 12px; }
        .btn-clear:hover { background: #7f8c8d; }
        .btn-delete { background: #e74c3c; color: white; font-size: 12px; padding: 6px 12px; }
        .btn-delete:hover { background: #c0392b; }
        .last-seen { font-size: 11px; }
        .last-seen.recent { color: #27ae60; }
        .last-seen.stale { color: #e74c3c; }
        .table-container { max-height: 600px; overflow-y: auto; }
        /* Search and Filter Styles */
        .search-box { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; width: 250px; }
        .search-box:focus { outline: none; border-color: #3498db; box-shadow: 0 0 0 2px rgba(52,152,219,0.2); }
        .filter-group { display: flex; align-items: center; gap: 8px; }
        .filter-group label { font-size: 13px; color: #666; }
        .filter-select { padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; background: white; cursor: pointer; }
        /* Vault status indicator */
        .vault-status { display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: rgba(255,255,255,0.1); border-radius: 4px; font-size: 13px; }
        .vault-status-dot { width: 10px; height: 10px; border-radius: 50%; }
        .vault-status-dot.healthy { background: #27ae60; box-shadow: 0 0 6px #27ae60; }
        .vault-status-dot.unhealthy { background: #e74c3c; box-shadow: 0 0 6px #e74c3c; }
        .vault-status-dot.unknown { background: #f39c12; box-shadow: 0 0 6px #f39c12; }
        .vault-status-text { color: rgba(255,255,255,0.9); }
        .vault-status-details { font-size: 11px; color: rgba(255,255,255,0.6); }
        .filter-select:focus { outline: none; border-color: #3498db; }
        .result-count { font-size: 13px; color: #666; margin-left: 10px; }
        .filters-bar { padding: 12px 20px; background: #f8f9fa; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
        .version-badge { font-size: 12px; font-weight: normal; background: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 4px; margin-left: 10px; vertical-align: middle; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div style="display: flex; align-items: center; gap: 20px;">
                <h1>System Dashboard <span class="version-badge">{{.Version}}</span></h1>
                <div class="vault-status" id="vault-status" title="Vault Status">
                    <div class="vault-status-dot unknown" id="vault-status-dot"></div>
                    <div>
                        <div class="vault-status-text" id="vault-status-text">Vault: Checking...</div>
                        <div class="vault-status-details" id="vault-status-details"></div>
                    </div>
                </div>
            </div>
            <nav class="nav-links">
                <a href="/">Bootstrap Requests</a>
                <a href="/system">Registered Agents</a>
                <a href="/alerts">Alerts</a>
                <a href="/manual-bootstrap">Manual Bootstrap</a>
                <a href="/audit">Audit Log</a>
            </nav>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{{.Stats.TotalAgents}}</div>
                <div class="label">Total Agents</div>
            </div>
            <div class="stat-card active">
                <div class="number">{{.Stats.ActiveAgents}}</div>
                <div class="label">Active (5m)</div>
            </div>
            <div class="stat-card ca-ready">
                <div class="number">{{.Stats.CAReadyAgents}}</div>
                <div class="label">CA Ready</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Registered Agents (<span id="visible-count">{{len .Registrations}}</span> / {{len .Registrations}})</h2>
                <div class="header-controls">
                    <button class="btn btn-refresh" onclick="location.reload()">Refresh</button>
                </div>
            </div>
            {{if .Registrations}}
            <div class="filters-bar">
                <input type="text" id="search-box" class="search-box" placeholder="Search hostname, agent ID, IP..." autofocus>
                <div class="filter-group">
                    <label>Status:</label>
                    <select id="filter-status" class="filter-select">
                        <option value="all">All</option>
                        <option value="active">Active (5m)</option>
                        <option value="stale">Stale</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>CA:</label>
                    <select id="filter-ca" class="filter-select">
                        <option value="all">All</option>
                        <option value="ready">Ready</option>
                        <option value="not-ready">Not Ready</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>PoW:</label>
                    <select id="filter-pow" class="filter-select">
                        <option value="all">All</option>
                        <option value="ok">OK</option>
                        <option value="warning">Warning</option>
                        <option value="failed">Failed</option>
                        <option value="disabled">Disabled</option>
                    </select>
                </div>
                <button class="btn btn-clear" onclick="clearFilters()">Clear Filters</button>
            </div>
            <div class="table-container">
            <table id="agents-table">
                <thead>
                    <tr>
                        <th>Agent ID</th>
                        <th>Hostname</th>
                        <th>OS / Arch</th>
                        <th>Version</th>
                        <th>IP Addresses</th>
                        <th>CA Status</th>
                        <th>PoW Status</th>
                        <th>Uptime</th>
                        <th>Last Seen</th>
                        <th>Heartbeats</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="agents-tbody">
                {{range .Registrations}}
                <tr data-agent-id="{{.AgentID}}"
                    data-hostname="{{.Hostname}}"
                    data-client-ip="{{.ClientIP}}"
                    data-ips="{{range .IPAddresses}}{{.}} {{end}}"
                    data-ca-ready="{{if .CAStatus}}{{if .CAStatus.Ready}}yes{{else}}no{{end}}{{else}}no{{end}}"
                    data-pow-status="{{.PoWStatus}}"
                    data-last-seen="{{.LastSeenAt.Unix}}">
                    <td class="mono">{{.AgentID}}</td>
                    <td><strong>{{.Hostname}}</strong><br><span class="mono" style="font-size:10px">{{.ClientIP}}</span></td>
                    <td>{{.OS}} / {{.Arch}}<br><span style="font-size:11px;color:#666">{{.OSVersion}}</span></td>
                    <td class="mono">{{.AgentVersion}}</td>
                    <td class="ip-list mono">{{range .IPAddresses}}{{.}}<br>{{end}}</td>
                    <td>
                        {{if .CAStatus}}
                            {{if .CAStatus.Ready}}<span class="badge badge-ready">Ready</span>{{else}}<span class="badge badge-not-ready">Not Ready</span>{{end}}
                            <div class="ca-info">
                                {{if .CAStatus.RemainingTTL}}<span class="expires">TTL: {{.CAStatus.RemainingTTL}}</span>{{end}}
                                {{if .CAStatus.RenewalMethod}}<br>Method: {{.CAStatus.RenewalMethod}}{{end}}
                            </div>
                        {{else}}
                            <span class="badge badge-not-ready">N/A</span>
                        {{end}}
                    </td>
                    <td>
                        {{if eq .PoWStatus "ok"}}<span class="badge badge-pow-ok">OK</span>
                        {{else if eq .PoWStatus "warning"}}<span class="badge badge-pow-warning">Warning</span>
                        {{else if eq .PoWStatus "failed"}}<span class="badge badge-pow-failed">Failed</span>
                        {{else}}<span class="badge badge-pow-disabled">Disabled</span>
                        {{end}}
                        {{if .PoWVerification}}
                        <div class="pow-info">
                            {{if .SecureHeartbeat}}Seq: {{.SecureHeartbeat.Sequence}}{{end}}
                            {{if gt .PoWVerification.WitnessCount 0}}<br>W: {{.PoWVerification.WitnessCount}}/{{.PoWVerification.WitnessThreshold}}{{end}}
                            {{range .PoWVerification.Errors}}<br><span class="error">{{.}}</span>{{end}}
                            {{range .PoWVerification.Warnings}}<br><span class="warning">{{.}}</span>{{end}}
                        </div>
                        {{end}}
                    </td>
                    <td>{{printf "%.1f" (divf .UptimeSeconds 3600)}}h</td>
                    <td class="last-seen">{{.LastSeenAt.Format "Jan 02 15:04:05"}}</td>
                    <td>{{.RegisterCount}}</td>
                    <td><button class="btn btn-delete" onclick="deleteRegistration('{{.AgentID}}', '{{.Hostname}}')" title="Delete registration">Delete</button></td>
                </tr>
                {{end}}
                </tbody>
            </table>
            <div id="no-results" class="no-results">No agents match your search criteria</div>
            </div>
            <!-- Pagination Controls -->
            <div class="pagination-controls" style="padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #eee;">
                <div class="pagination-info" style="color: #666; font-size: 14px;">
                    Showing {{len .Registrations}} of {{.Pagination.Total}} agents (Page {{.Pagination.CurrentPage}} of {{.Pagination.TotalPages}})
                </div>
                <div class="pagination-buttons" style="display: flex; gap: 10px;">
                    {{if .Pagination.HasPrev}}
                    <a href="/system?offset={{.Pagination.PrevOffset}}&limit={{.Pagination.Limit}}" class="btn" style="background: #3498db; color: white; text-decoration: none;">← Previous</a>
                    {{else}}
                    <span class="btn" style="background: #ccc; color: #666; cursor: not-allowed;">← Previous</span>
                    {{end}}
                    {{if .Pagination.HasNext}}
                    <a href="/system?offset={{.Pagination.NextOffset}}&limit={{.Pagination.Limit}}" class="btn" style="background: #3498db; color: white; text-decoration: none;">Next →</a>
                    {{else}}
                    <span class="btn" style="background: #ccc; color: #666; cursor: not-allowed;">Next →</span>
                    {{end}}
                </div>
            </div>
            {{else}}
            <div class="empty">No agents registered yet. Enable registration on agents with registration_enabled: true</div>
            {{end}}
        </div>
    </div>

    <script>
        // Vault status polling
        function updateVaultStatus() {
            fetch('/api/vault-status')
                .then(r => r.json())
                .then(status => {
                    const dot = document.getElementById('vault-status-dot');
                    const text = document.getElementById('vault-status-text');
                    const details = document.getElementById('vault-status-details');
                    dot.className = 'vault-status-dot ' + (status.healthy ? 'healthy' : 'unhealthy');
                    if (status.healthy) {
                        text.textContent = 'Vault: Connected';
                        let detailText = status.version || '';
                        if (status.standby) detailText += ' (standby)';
                        if (status.response_time_ms) detailText += ' · ' + status.response_time_ms + 'ms';
                        details.textContent = detailText;
                    } else {
                        text.textContent = 'Vault: ' + (status.error || 'Unhealthy');
                        details.textContent = status.sealed ? 'Sealed' : (status.initialized ? '' : 'Not initialized');
                    }
                })
                .catch(err => {
                    document.getElementById('vault-status-dot').className = 'vault-status-dot unhealthy';
                    document.getElementById('vault-status-text').textContent = 'Vault: Error';
                    document.getElementById('vault-status-details').textContent = err.message || 'Connection failed';
                });
        }
        updateVaultStatus();
        setInterval(updateVaultStatus, 20000);

        const searchBox = document.getElementById('search-box');
        const filterStatus = document.getElementById('filter-status');
        const filterCA = document.getElementById('filter-ca');
        const filterPoW = document.getElementById('filter-pow');
        const tbody = document.getElementById('agents-tbody');
        const visibleCount = document.getElementById('visible-count');
        const noResults = document.getElementById('no-results');
        const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 300;

        function applyFilters() {
            if (!tbody) return;

            const searchTerm = searchBox.value.toLowerCase().trim();
            const statusFilter = filterStatus.value;
            const caFilter = filterCA.value;
            const powFilter = filterPoW ? filterPoW.value : 'all';

            const rows = tbody.querySelectorAll('tr');
            let visible = 0;

            rows.forEach(row => {
                let show = true;

                // Search filter (hostname, agent ID, IPs)
                if (searchTerm) {
                    const agentId = (row.dataset.agentId || '').toLowerCase();
                    const hostname = (row.dataset.hostname || '').toLowerCase();
                    const clientIp = (row.dataset.clientIp || '').toLowerCase();
                    const ips = (row.dataset.ips || '').toLowerCase();

                    if (!agentId.includes(searchTerm) &&
                        !hostname.includes(searchTerm) &&
                        !clientIp.includes(searchTerm) &&
                        !ips.includes(searchTerm)) {
                        show = false;
                    }
                }

                // Status filter (active/stale based on last seen)
                if (show && statusFilter !== 'all') {
                    const lastSeen = parseInt(row.dataset.lastSeen) || 0;
                    const isActive = lastSeen >= fiveMinutesAgo;
                    if (statusFilter === 'active' && !isActive) show = false;
                    if (statusFilter === 'stale' && isActive) show = false;
                }

                // CA filter
                if (show && caFilter !== 'all') {
                    const caReady = row.dataset.caReady === 'yes';
                    if (caFilter === 'ready' && !caReady) show = false;
                    if (caFilter === 'not-ready' && caReady) show = false;
                }

                // PoW filter
                if (show && powFilter !== 'all') {
                    const powStatus = row.dataset.powStatus || 'disabled';
                    if (powFilter !== powStatus) show = false;
                }

                row.classList.toggle('hidden', !show);
                if (show) visible++;
            });

            visibleCount.textContent = visible;
            noResults.style.display = (visible === 0 && rows.length > 0) ? 'block' : 'none';
        }

        function clearFilters() {
            searchBox.value = '';
            filterStatus.value = 'all';
            filterCA.value = 'all';
            if (filterPoW) filterPoW.value = 'all';
            applyFilters();
            searchBox.focus();
        }

        // Event listeners
        if (searchBox) {
            searchBox.addEventListener('input', applyFilters);
            searchBox.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    clearFilters();
                }
            });
        }
        if (filterStatus) filterStatus.addEventListener('change', applyFilters);
        if (filterCA) filterCA.addEventListener('change', applyFilters);
        if (filterPoW) filterPoW.addEventListener('change', applyFilters);

        // Preserve search on refresh (using URL hash)
        function saveState() {
            const state = {
                search: searchBox?.value || '',
                status: filterStatus?.value || 'all',
                ca: filterCA?.value || 'all',
                pow: filterPoW?.value || 'all'
            };
            if (state.search || state.status !== 'all' || state.ca !== 'all' || state.pow !== 'all') {
                location.hash = encodeURIComponent(JSON.stringify(state));
            } else {
                history.replaceState(null, '', location.pathname);
            }
        }

        function loadState() {
            if (location.hash) {
                try {
                    const state = JSON.parse(decodeURIComponent(location.hash.slice(1)));
                    if (searchBox && state.search) searchBox.value = state.search;
                    if (filterStatus && state.status) filterStatus.value = state.status;
                    if (filterCA && state.ca) filterCA.value = state.ca;
                    if (filterPoW && state.pow) filterPoW.value = state.pow;
                    applyFilters();
                } catch (e) {}
            }
        }

        // Save state before refresh
        if (searchBox) searchBox.addEventListener('input', saveState);
        if (filterStatus) filterStatus.addEventListener('change', saveState);
        if (filterCA) filterCA.addEventListener('change', saveState);
        if (filterPoW) filterPoW.addEventListener('change', saveState);

        // Load state on page load
        loadState();

        // Auto-refresh every 60 seconds
        setTimeout(() => location.reload(), 60000);

        // Delete registration function
        async function deleteRegistration(agentId, hostname) {
            if (!confirm('Delete registration for ' + hostname + ' (' + agentId + ')?')) {
                return;
            }
            try {
                const resp = await fetch('/api/systems/' + encodeURIComponent(agentId), { method: 'DELETE' });
                if (resp.ok) {
                    alert('Registration deleted successfully');
                    location.reload();
                } else {
                    const error = await resp.text();
                    alert('Failed to delete registration: ' + error);
                }
            } catch (e) {
                alert('Error: ' + e.message);
            }
        }
    </script>
</body>
</html>`

// handleAuditLog returns audit log entries
// @Summary Get audit log
// @Description Returns audit log entries with optional filtering by hostname or event type
// @Tags Admin
// @Produce json
// @Param limit query int false "Maximum number of entries to return" default(100)
// @Param hostname query string false "Filter by hostname"
// @Param event_type query string false "Filter by event type (approval, denial, token_delivered, etc.)"
// @Success 200 {array} types.AuditEntry "List of audit entries"
// @Failure 401 {string} string "Unauthorized"
// @Security BasicAuth
// @Router /api/audit [get]
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	var entries []*types.AuditEntry

	hostname := r.URL.Query().Get("hostname")
	eventType := r.URL.Query().Get("event_type")

	if hostname != "" {
		entries = s.store.ListAuditLogByHostname(hostname, limit)
	} else if eventType != "" {
		entries = s.store.ListAuditLogByEventType(types.AuditEventType(eventType), limit)
	} else {
		entries = s.store.ListAuditLog(limit)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleAuditDashboard serves the audit log dashboard
// GET /audit
func (s *Server) handleAuditDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/audit" && r.URL.Path != "/audit/" {
		http.NotFound(w, r)
		return
	}

	entries := s.store.ListAuditLog(200)

	data := struct {
		Entries []*types.AuditEntry
		Version string
	}{
		Entries: entries,
		Version: version.Version,
	}

	tmpl, err := template.New("audit").Parse(auditDashboardTemplate)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

// Audit dashboard HTML template
const auditDashboardTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Audit Log - Bootstrap Server</title>
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
        .section { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; overflow: hidden; }
        .section-header { padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .section-header h2 { font-size: 18px; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #555; }
        tr:hover { background: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .badge-approval { background: #d4edda; color: #155724; }
        .badge-denial { background: #f8d7da; color: #721c24; }
        .badge-token { background: #cce5ff; color: #004085; }
        .badge-reset { background: #fff3cd; color: #856404; }
        .badge-auto { background: #e2e3e5; color: #383d41; }
        .empty { padding: 40px; text-align: center; color: #666; }
        .search-box { padding: 10px 20px; border-bottom: 1px solid #eee; }
        .search-box input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .ip-list { font-family: monospace; font-size: 12px; }
        .version-badge { font-size: 12px; font-weight: normal; background: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 4px; margin-left: 10px; vertical-align: middle; }
        /* Vault status indicator */
        .vault-status { display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: rgba(255,255,255,0.1); border-radius: 4px; font-size: 13px; }
        .vault-status-dot { width: 10px; height: 10px; border-radius: 50%; }
        .vault-status-dot.healthy { background: #27ae60; box-shadow: 0 0 6px #27ae60; }
        .vault-status-dot.unhealthy { background: #e74c3c; box-shadow: 0 0 6px #e74c3c; }
        .vault-status-dot.unknown { background: #f39c12; box-shadow: 0 0 6px #f39c12; }
        .vault-status-text { color: rgba(255,255,255,0.9); }
        .vault-status-details { font-size: 11px; color: rgba(255,255,255,0.6); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div style="display: flex; align-items: center; gap: 20px;">
                <h1>Audit Log <span class="version-badge">{{.Version}}</span></h1>
                <div class="vault-status" id="vault-status" title="Vault Status">
                    <div class="vault-status-dot unknown" id="vault-status-dot"></div>
                    <div>
                        <div class="vault-status-text" id="vault-status-text">Vault: Checking...</div>
                        <div class="vault-status-details" id="vault-status-details"></div>
                    </div>
                </div>
            </div>
            <nav class="nav-links">
                <a href="/">Bootstrap Requests</a>
                <a href="/system">Registered Agents</a>
                <a href="/alerts">Alerts</a>
                <a href="/manual-bootstrap">Manual Bootstrap</a>
                <a href="/audit">Audit Log</a>
            </nav>
        </header>

        <div class="section">
            <div class="section-header">
                <h2>Recent Events <span class="badge">{{len .Entries}}</span></h2>
            </div>
            <div class="search-box">
                <input type="text" id="search-box" placeholder="Search by hostname, performed by, event type..." onkeyup="filterTable()">
            </div>
            {{if .Entries}}
            <table id="audit-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event</th>
                        <th>Hostname</th>
                        <th>OS / Arch</th>
                        <th>Performed By</th>
                        <th>Token ID</th>
                        <th>Reason / Details</th>
                    </tr>
                </thead>
                <tbody>
                {{range .Entries}}
                <tr data-searchable="{{.Hostname}} {{.PerformedBy}} {{.EventType}} {{.Reason}}">
                    <td>{{.Timestamp.Format "2006-01-02 15:04:05"}}</td>
                    <td>
                        {{if eq (printf "%s" .EventType) "approval"}}<span class="badge badge-approval">Approval</span>
                        {{else if eq (printf "%s" .EventType) "denial"}}<span class="badge badge-denial">Denial</span>
                        {{else if eq (printf "%s" .EventType) "token_delivered"}}<span class="badge badge-token">Token Delivered</span>
                        {{else if eq (printf "%s" .EventType) "reset_to_pending"}}<span class="badge badge-reset">Reset to Pending</span>
                        {{else if eq (printf "%s" .EventType) "auto_approval"}}<span class="badge badge-auto">Auto Approval</span>
                        {{else}}<span class="badge">{{.EventType}}</span>{{end}}
                    </td>
                    <td><strong>{{.Hostname}}</strong><br><span class="ip-list">{{.ClientIP}}</span></td>
                    <td>{{.OS}} / {{.Arch}}</td>
                    <td>{{.PerformedBy}}</td>
                    <td><span class="ip-list">{{if .TokenID}}{{.TokenID}}{{else}}-{{end}}</span></td>
                    <td>{{if .Reason}}{{.Reason}}{{else}}-{{end}}</td>
                </tr>
                {{end}}
                </tbody>
            </table>
            {{else}}
            <div class="empty">No audit entries yet. Approve or deny some bootstrap requests to see them here.</div>
            {{end}}
        </div>
    </div>

    <script>
        // Vault status polling
        function updateVaultStatus() {
            fetch('/api/vault-status')
                .then(r => r.json())
                .then(status => {
                    const dot = document.getElementById('vault-status-dot');
                    const text = document.getElementById('vault-status-text');
                    const details = document.getElementById('vault-status-details');
                    dot.className = 'vault-status-dot ' + (status.healthy ? 'healthy' : 'unhealthy');
                    if (status.healthy) {
                        text.textContent = 'Vault: Connected';
                        let detailText = status.version || '';
                        if (status.standby) detailText += ' (standby)';
                        if (status.response_time_ms) detailText += ' · ' + status.response_time_ms + 'ms';
                        details.textContent = detailText;
                    } else {
                        text.textContent = 'Vault: ' + (status.error || 'Unhealthy');
                        details.textContent = status.sealed ? 'Sealed' : (status.initialized ? '' : 'Not initialized');
                    }
                })
                .catch(err => {
                    document.getElementById('vault-status-dot').className = 'vault-status-dot unhealthy';
                    document.getElementById('vault-status-text').textContent = 'Vault: Error';
                    document.getElementById('vault-status-details').textContent = err.message || 'Connection failed';
                });
        }
        updateVaultStatus();
        setInterval(updateVaultStatus, 20000);

        function filterTable() {
            const searchTerm = document.getElementById('search-box').value.toLowerCase();
            const rows = document.querySelectorAll('#audit-table tbody tr');

            rows.forEach(row => {
                const searchable = (row.dataset.searchable || '').toLowerCase();
                row.style.display = searchable.includes(searchTerm) ? '' : 'none';
            });
        }
    </script>
</body>
</html>`

// ManualBootstrapRequest represents a request for manual token generation
type ManualBootstrapRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Role     string `json:"role,omitempty"`
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

// handleManualBootstrap generates a bootstrap token manually without a machine request
// @Summary Generate manual bootstrap token
// @Description Generates a bootstrap token for a machine without requiring a bootstrap request
// @Tags Admin
// @Accept json
// @Produce json
// @Param request body ManualBootstrapRequest true "Manual bootstrap request"
// @Success 200 {object} types.BootstrapToken "Generated bootstrap token"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Failed to generate token"
// @Security BasicAuth
// @Router /api/manual-bootstrap [post]
func (s *Server) handleManualBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ManualBootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		jsonError(w, "Hostname is required", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		jsonError(w, "Username is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "Reason is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.OS == "" {
		req.OS = "unknown"
	}
	if req.Arch == "" {
		req.Arch = "unknown"
	}

	// Create a minimal MachineRequest for token generation
	machineReq := &types.MachineRequest{
		ID:        fmt.Sprintf("manual-%d", time.Now().UnixNano()),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Hostname:  req.Hostname,
		OS:        req.OS,
		Arch:      req.Arch,
		Status:    types.StatusApproved,
	}

	// Generate the bootstrap token
	token, _, err := s.generateTokenForAgent(machineReq)
	if err != nil {
		log.Printf("Failed to generate manual bootstrap token for %s: %v", req.Hostname, err)
		jsonError(w, fmt.Sprintf("Failed to generate token: %v", err), http.StatusInternalServerError)
		return
	}

	// Get client IP for audit
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = strings.Split(forwarded, ",")[0]
	}

	// Add audit entry
	s.store.AddAuditEntry(&types.AuditEntry{
		Timestamp:   time.Now(),
		EventType:   types.AuditEventManualBootstrap,
		RequestID:   machineReq.ID,
		Hostname:    req.Hostname,
		OS:          req.OS,
		Arch:        req.Arch,
		PerformedBy: req.Username,
		Reason:      req.Reason,
		TokenID:     token.TokenID,
		ClientIP:    clientIP,
		Details:     fmt.Sprintf(`{"role":"%s"}`, token.Role),
	})

	log.Printf("Manual bootstrap token generated for %s by %s: %s", req.Hostname, req.Username, req.Reason)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

// handleManualBootstrapPage serves the manual bootstrap web page
// GET /manual-bootstrap
func (s *Server) handleManualBootstrapPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/manual-bootstrap" && r.URL.Path != "/manual-bootstrap/" {
		http.NotFound(w, r)
		return
	}

	data := struct {
		Version string
	}{
		Version: version.Version,
	}

	tmpl, err := template.New("manual-bootstrap").Parse(manualBootstrapTemplate)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

const manualBootstrapTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Manual Bootstrap - MID Bootstrap Server</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/svg+xml" href="/favicon.ico">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }
        header h1 { font-size: 24px; }
        .nav-links { display: flex; gap: 15px; }
        .nav-links a { color: white; text-decoration: none; padding: 8px 16px; background: rgba(255,255,255,0.1); border-radius: 4px; }
        .nav-links a:hover { background: rgba(255,255,255,0.2); }
        .section { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; overflow: hidden; }
        .section-header { padding: 15px 20px; border-bottom: 1px solid #eee; }
        .section-header h2 { font-size: 18px; color: #333; }
        .section-body { padding: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 500; color: #333; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .form-group input:focus, .form-group textarea:focus, .form-group select:focus { outline: none; border-color: #3498db; box-shadow: 0 0 0 2px rgba(52,152,219,0.2); }
        .form-group textarea { min-height: 80px; resize: vertical; }
        .form-group .hint { font-size: 12px; color: #888; margin-top: 4px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .btn { padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 500; }
        .btn-primary { background: #3498db; color: white; }
        .btn-primary:hover { background: #2980b9; }
        .btn-primary:disabled { background: #95a5a6; cursor: not-allowed; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; display: none; }
        .result.success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .result.error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .token-display { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 15px; font-family: 'SF Mono', Monaco, monospace; font-size: 13px; word-break: break-all; }
        .token-display .label { font-weight: 600; color: #333; margin-bottom: 5px; }
        .token-display .value { color: #27ae60; }
        .copy-btn { margin-top: 10px; padding: 8px 16px; font-size: 12px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .copy-btn:hover { background: #5a6268; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .warning strong { display: block; margin-bottom: 5px; }
        .version-badge { font-size: 12px; font-weight: normal; background: rgba(255,255,255,0.2); padding: 4px 8px; border-radius: 4px; margin-left: 10px; }
        /* Vault status indicator */
        .vault-status { display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: rgba(255,255,255,0.1); border-radius: 4px; font-size: 13px; }
        .vault-status-dot { width: 10px; height: 10px; border-radius: 50%; }
        .vault-status-dot.healthy { background: #27ae60; box-shadow: 0 0 6px #27ae60; }
        .vault-status-dot.unhealthy { background: #e74c3c; box-shadow: 0 0 6px #e74c3c; }
        .vault-status-dot.unknown { background: #f39c12; box-shadow: 0 0 6px #f39c12; }
        .vault-status-text { color: rgba(255,255,255,0.9); }
        .vault-status-details { font-size: 11px; color: rgba(255,255,255,0.6); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div style="display: flex; align-items: center; gap: 20px;">
                <h1>Manual Bootstrap <span class="version-badge">{{.Version}}</span></h1>
                <div class="vault-status" id="vault-status" title="Vault Status">
                    <div class="vault-status-dot unknown" id="vault-status-dot"></div>
                    <div>
                        <div class="vault-status-text" id="vault-status-text">Vault: Checking...</div>
                        <div class="vault-status-details" id="vault-status-details"></div>
                    </div>
                </div>
            </div>
            <nav class="nav-links">
                <a href="/">Bootstrap Requests</a>
                <a href="/system">Registered Agents</a>
                <a href="/alerts">Alerts</a>
                <a href="/manual-bootstrap">Manual Bootstrap</a>
                <a href="/audit">Audit Log</a>
            </nav>
        </header>

        <div class="warning">
            <strong>⚠️ Manual Bootstrap</strong>
            Use this feature only when a machine cannot reach the bootstrap server directly (e.g., network issues, air-gapped environment).
            The generated token should be manually delivered to the machine and used with pki-mid-auth.
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Generate Bootstrap Token</h2>
            </div>
            <div class="section-body">
                <form id="bootstrap-form" onsubmit="generateToken(event)">
                    <div class="form-group">
                        <label for="hostname">Hostname *</label>
                        <input type="text" id="hostname" name="hostname" required placeholder="e.g., pi-163, server-001">
                        <div class="hint">The hostname of the machine to bootstrap</div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label for="os">Operating System</label>
                            <select id="os" name="os">
                                <option value="">Unknown</option>
                                <option value="linux">Linux</option>
                                <option value="darwin">macOS</option>
                                <option value="windows">Windows</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="arch">Architecture</label>
                            <select id="arch" name="arch">
                                <option value="">Unknown</option>
                                <option value="amd64">amd64 (x86_64)</option>
                                <option value="arm64">arm64 (aarch64)</option>
                                <option value="arm">arm (32-bit)</option>
                                <option value="386">386 (x86)</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="username">Your Name *</label>
                        <input type="text" id="username" name="username" required placeholder="e.g., John Doe">
                        <div class="hint">For audit purposes - who is generating this token</div>
                    </div>

                    <div class="form-group">
                        <label for="reason">Reason *</label>
                        <textarea id="reason" name="reason" required placeholder="e.g., Machine cannot reach bootstrap server due to network segmentation. Token will be delivered manually via USB."></textarea>
                        <div class="hint">Why is manual bootstrap needed? This will be recorded in the audit log.</div>
                    </div>

                    <button type="submit" class="btn btn-primary" id="submit-btn">Generate Token</button>
                </form>

                <div id="result" class="result"></div>
            </div>
        </div>
    </div>

    <script>
        // Vault status polling
        function updateVaultStatus() {
            fetch('/api/vault-status')
                .then(r => r.json())
                .then(status => {
                    const dot = document.getElementById('vault-status-dot');
                    const text = document.getElementById('vault-status-text');
                    const details = document.getElementById('vault-status-details');
                    dot.className = 'vault-status-dot ' + (status.healthy ? 'healthy' : 'unhealthy');
                    if (status.healthy) {
                        text.textContent = 'Vault: Connected';
                        let detailText = status.version || '';
                        if (status.standby) detailText += ' (standby)';
                        if (status.response_time_ms) detailText += ' · ' + status.response_time_ms + 'ms';
                        details.textContent = detailText;
                    } else {
                        text.textContent = 'Vault: ' + (status.error || 'Unhealthy');
                        details.textContent = status.sealed ? 'Sealed' : (status.initialized ? '' : 'Not initialized');
                    }
                })
                .catch(err => {
                    document.getElementById('vault-status-dot').className = 'vault-status-dot unhealthy';
                    document.getElementById('vault-status-text').textContent = 'Vault: Error';
                    document.getElementById('vault-status-details').textContent = err.message || 'Connection failed';
                });
        }
        updateVaultStatus();
        setInterval(updateVaultStatus, 20000);

        async function generateToken(event) {
            event.preventDefault();

            const submitBtn = document.getElementById('submit-btn');
            const resultDiv = document.getElementById('result');

            submitBtn.disabled = true;
            submitBtn.textContent = 'Generating...';
            resultDiv.style.display = 'none';

            const data = {
                hostname: document.getElementById('hostname').value,
                os: document.getElementById('os').value || 'unknown',
                arch: document.getElementById('arch').value || 'unknown',
                username: document.getElementById('username').value,
                reason: document.getElementById('reason').value
            };

            try {
                const response = await fetch('/api/manual-bootstrap', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                if (!response.ok) {
                    const error = await response.text();
                    throw new Error(error);
                }

                const token = await response.json();

                resultDiv.className = 'result success';
                resultDiv.innerHTML = ` + "`" + `
                    <strong>✓ Token Generated Successfully</strong>
                    <p style="margin-top: 10px;">Deliver this token to the machine and run:</p>
                    <div class="token-display">
                        <div class="label">Bootstrap Command:</div>
                        <div class="value">mag bootstrap --token "${token.token}"</div>
                    </div>
                    <div class="token-display">
                        <div class="label">Token ID:</div>
                        <div class="value">${token.token_id}</div>
                    </div>
                    <div class="token-display">
                        <div class="label">Expires:</div>
                        <div class="value">${new Date(token.expires_at).toLocaleString()}</div>
                    </div>
                    <button class="copy-btn" onclick="copyToClipboard('${token.token}')">Copy Token</button>
                ` + "`" + `;
                resultDiv.style.display = 'block';

                // Clear form
                document.getElementById('bootstrap-form').reset();

            } catch (error) {
                resultDiv.className = 'result error';
                resultDiv.innerHTML = ` + "`" + `<strong>✗ Error</strong><p>${error.message}</p>` + "`" + `;
                resultDiv.style.display = 'block';
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Generate Token';
            }
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Token copied to clipboard!');
            }).catch(err => {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = text;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                alert('Token copied to clipboard!');
            });
        }
    </script>
</body>
</html>`
