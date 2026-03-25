package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"

	"mid-bootstrap-server.git/docs"
	"mid-bootstrap-server.git/internal/auth"
	"mid-bootstrap-server.git/internal/config"
	"mid-bootstrap-server.git/internal/pow"
	"mid-bootstrap-server.git/internal/store"
	"mid-bootstrap-server.git/internal/types"
	"mid-bootstrap-server.git/internal/vault"
)

// Server is the main bootstrap server
type Server struct {
	config             *config.Config
	store              store.Store
	vaultClient        *vault.Client
	httpServer         *http.Server
	mux                *http.ServeMux
	auth               auth.Authenticator
	registrationCAPool *x509.CertPool // CA pool for verifying registration client certs
	wsHub              *WebSocketHub  // WebSocket hub for real-time events
	powVerifier        *pow.Verifier  // PoW verifier for anti-spoofing (advisory mode)
	alertService       *AlertService  // Alert service for stale agents and version changes

	// Vault health status
	vaultHealthMu     sync.RWMutex
	vaultHealthStatus *vault.VaultHealthStatus
}

// NewServer creates a new bootstrap server
func NewServer(cfg *config.Config) (*Server, error) {
	// Create Vault client
	vaultClient, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Verify Vault connectivity
	if err := vaultClient.HealthCheck(); err != nil {
		log.Printf("WARNING: Vault health check failed: %v", err)
	}

	// Verify Vault token
	if cfg.VaultToken != "" {
		if err := vaultClient.ValidateToken(); err != nil {
			log.Printf("WARNING: Vault token validation failed: %v", err)
		}
	}

	// Create authenticator based on config
	authenticator, err := createAuthenticator(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	// Initialize store based on config
	var dataStore store.Store
	switch cfg.StoreType {
	case "sqlite":
		sqliteStore, storeErr := store.NewSQLiteStore(cfg.StorePath)
		if storeErr != nil {
			return nil, fmt.Errorf("failed to create SQLite store: %w", storeErr)
		}
		dataStore = sqliteStore
		log.Printf("Using SQLite store: %s", cfg.StorePath)
	default:
		dataStore = store.NewMemoryStore()
		log.Printf("Using in-memory store")
	}

	// Create alert service
	staleAgentMinutes := cfg.AlertStaleAgentMinutes
	if staleAgentMinutes <= 0 {
		staleAgentMinutes = 10 // Default: 10 minutes
	}

	s := &Server{
		config:       cfg,
		store:        dataStore,
		vaultClient:  vaultClient,
		mux:          http.NewServeMux(),
		auth:         authenticator,
		wsHub:        NewWebSocketHub(),
		powVerifier:  pow.NewVerifier(16, 2), // difficulty=16, witnessThreshold=2
		alertService: NewAlertService(dataStore, staleAgentMinutes),
	}

	// Load CA certificate for registration mTLS if configured
	if cfg.RegistrationRequireMTLS && cfg.RegistrationCACert != "" {
		caCert, err := os.ReadFile(cfg.RegistrationCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read registration CA cert: %w", err)
		}
		s.registrationCAPool = x509.NewCertPool()
		if !s.registrationCAPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse registration CA cert")
		}
		log.Printf("Registration mTLS enabled with CA: %s", cfg.RegistrationCACert)
	}

	// Register routes
	s.registerRoutes()

	// Create HTTP server with CORS support
	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.corsMiddleware(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// registerRoutes sets up all HTTP routes
func (s *Server) registerRoutes() {
	// Bootstrap API endpoints (no auth - agents need to access these)
	s.mux.HandleFunc("/bootstrap/", s.handleBootstrap)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/version", s.handleVersion)

	// Agent registration endpoint (no auth - agents send heartbeats here)
	s.mux.HandleFunc("/registration", s.handleRegistration)

	// Admin API endpoints (protected by auth)
	s.mux.HandleFunc("/api/requests", s.requireAuth(s.handleListRequests))
	s.mux.HandleFunc("/api/requests/", s.requireAuth(s.handleRequest))
	s.mux.HandleFunc("/api/approve", s.requireAuth(s.handleApprove))
	s.mux.HandleFunc("/api/deny", s.requireAuth(s.handleDeny))
	s.mux.HandleFunc("/api/generate-token", s.requireAuth(s.handleGenerateToken))
	s.mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	s.mux.HandleFunc("/api/systems", s.requireAuth(s.handleListRegistrations))
	s.mux.HandleFunc("/api/systems/", s.requireAuth(s.handleRegistrationDelete))
	s.mux.HandleFunc("/api/system-stats", s.requireAuth(s.handleSystemStats))
	s.mux.HandleFunc("/api/audit", s.requireAuth(s.handleAuditLog))
	s.mux.HandleFunc("/api/manual-bootstrap", s.requireAuth(s.handleManualBootstrap))
	s.mux.HandleFunc("/api/vault-status", s.requireAuth(s.handleVaultStatus))

	// Alert API endpoints (protected by auth)
	s.mux.HandleFunc("/api/alerts", s.requireAuth(s.handleListAlerts))
	s.mux.HandleFunc("/api/alerts/", s.requireAuth(s.handleAlert))
	s.mux.HandleFunc("/api/alert-stats", s.requireAuth(s.handleAlertStats))

	// Web UI (protected by auth)
	if s.config.WebEnabled {
		s.mux.HandleFunc("/", s.requireAuth(s.handleDashboard))
		s.mux.HandleFunc("/system", s.requireAuth(s.handleSystemDashboard))
		s.mux.HandleFunc("/alerts", s.requireAuth(s.handleAlertsDashboard))
		s.mux.HandleFunc("/manual-bootstrap", s.requireAuth(s.handleManualBootstrapPage))
		s.mux.HandleFunc("/audit", s.requireAuth(s.handleAuditDashboard))
		s.mux.HandleFunc("/static/", s.handleStatic) // Static files don't need auth
		s.mux.HandleFunc("/favicon.ico", s.handleFavicon)
	}

	// WebSocket endpoint for real-time events (protected by auth)
	s.mux.HandleFunc("/ws", s.requireAuth(s.handleWebSocket))

	// Swagger API documentation (no auth - documentation should be accessible)
	// Clear host so Swagger UI uses the current page's host (same-origin requests)
	docs.SwaggerInfo.Host = ""
	s.mux.HandleFunc("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("list"),
		httpSwagger.DomID("swagger-ui"),
	))
}

// requireAuth wraps a handler with authentication middleware
func (s *Server) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return auth.MiddlewareFunc(s.auth, handler)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Start cleanup goroutine
	go s.cleanupLoop()

	// Start WebSocket hub
	go s.wsHub.Run()

	// Start Vault health check goroutine if enabled
	if s.config.VaultHealthCheckInterval > 0 {
		go s.vaultHealthCheckLoop()
		log.Printf("Vault health check enabled (interval: %s)", s.config.VaultHealthCheckInterval)
	}

	// Start alert service with stale agent checking
	alertCheckInterval := time.Duration(s.config.AlertCheckInterval) * time.Second
	if alertCheckInterval <= 0 {
		alertCheckInterval = 60 * time.Second // Default: check every minute
	}
	s.alertService.StartStaleAgentChecker(context.Background(), alertCheckInterval)
	log.Printf("Alert service started (stale threshold: %dm, check interval: %s)",
		s.config.AlertStaleAgentMinutes, alertCheckInterval)

	// Set up WebSocket notifications for alerts
	s.alertService.SetWebSocketCallback(func(alert *types.Alert) {
		s.wsHub.BroadcastAlert(alert)
	})

	log.Printf("Starting bootstrap server on %s", s.config.ListenAddr)

	if s.config.TLSEnabled() {
		// Build TLS configuration
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Set minimum TLS version
		if s.config.TLSMinVersion == "1.3" {
			tlsConfig.MinVersion = tls.VersionTLS13
		}

		// If mTLS is enabled for registration, request client certificates
		// We use RequestClientCert (not RequireAndVerifyClientCert) so that
		// other endpoints can still work without client certs.
		// The registration handler will verify the cert when required.
		if s.config.RegistrationRequireMTLS && s.registrationCAPool != nil {
			tlsConfig.ClientAuth = tls.RequestClientCert
			tlsConfig.ClientCAs = s.registrationCAPool
			log.Printf("TLS configured to request client certificates for mTLS")
		}

		s.httpServer.TLSConfig = tlsConfig
		return s.httpServer.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}
	return s.httpServer.ListenAndServe()
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
	// Close the store
	if err := s.store.Close(); err != nil {
		log.Printf("Warning: error closing store: %v", err)
	}
	return s.httpServer.Shutdown(ctx)
}

// cleanupLoop periodically cleans up expired requests
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		removed := s.store.CleanupExpired(s.config.RequestTTL)
		if removed > 0 {
			log.Printf("Cleaned up %d expired requests", removed)
		}
	}
}

// vaultHealthCheckLoop periodically checks Vault health
func (s *Server) vaultHealthCheckLoop() {
	// Do an initial check immediately
	s.updateVaultHealth()

	ticker := time.NewTicker(s.config.VaultHealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.updateVaultHealth()
	}
}

// updateVaultHealth fetches current Vault health and caches it
func (s *Server) updateVaultHealth() {
	status := s.vaultClient.GetHealthStatus()

	s.vaultHealthMu.Lock()
	s.vaultHealthStatus = status
	s.vaultHealthMu.Unlock()

	if !status.Healthy {
		log.Printf("Vault health check: unhealthy - %s", status.Error)
	}
}

// getVaultHealthStatus returns the cached Vault health status
func (s *Server) getVaultHealthStatus() *vault.VaultHealthStatus {
	s.vaultHealthMu.RLock()
	defer s.vaultHealthMu.RUnlock()

	if s.vaultHealthStatus == nil {
		// No cached status yet, do a live check
		return s.vaultClient.GetHealthStatus()
	}
	return s.vaultHealthStatus
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// generateNonce creates a random nonce for TPM attestation
func generateNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

// nonceToString converts a nonce to a hex string
func nonceToString(nonce []byte) string {
	return hex.EncodeToString(nonce)
}

// isFromTrustedNetwork checks if the client IP is from a trusted network
func (s *Server) isFromTrustedNetwork(clientIP string) bool {
	if len(s.config.TrustedNetworks) == 0 {
		return false
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, cidr := range s.config.TrustedNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// matchesReverseDNS checks if the client IP's reverse DNS matches the hostname
// Returns true if any reverse DNS name matches (case-insensitive)
func matchesReverseDNS(clientIP string, hostname string) bool {
	if clientIP == "" || hostname == "" {
		return false
	}

	// Perform reverse DNS lookup
	names, err := net.LookupAddr(clientIP)
	if err != nil {
		log.Printf("[DNS] Reverse lookup failed for %s: %v", clientIP, err)
		return false
	}

	if len(names) == 0 {
		log.Printf("[DNS] No reverse DNS names found for %s", clientIP)
		return false
	}

	// Normalize hostname for comparison (lowercase, remove trailing dot)
	normalizedHostname := strings.ToLower(strings.TrimSuffix(hostname, "."))

	for _, name := range names {
		// Normalize DNS name (lowercase, remove trailing dot)
		normalizedName := strings.ToLower(strings.TrimSuffix(name, "."))

		// Exact match
		if normalizedName == normalizedHostname {
			log.Printf("[DNS] Reverse DNS match: %s -> %s", clientIP, name)
			return true
		}

		// Check if hostname is a prefix (short name matches FQDN)
		// e.g., "server1" matches "server1.example.com"
		if strings.HasPrefix(normalizedName, normalizedHostname+".") {
			log.Printf("[DNS] Reverse DNS prefix match: %s -> %s (hostname: %s)", clientIP, name, hostname)
			return true
		}

		// Check if DNS name is a prefix of hostname
		// e.g., "server1.example.com" from DNS matches "server1.example.com.local" hostname
		if strings.HasPrefix(normalizedHostname, normalizedName+".") {
			log.Printf("[DNS] Reverse DNS suffix match: %s -> %s (hostname: %s)", clientIP, name, hostname)
			return true
		}
	}

	log.Printf("[DNS] No reverse DNS match for %s (names: %v, hostname: %s)", clientIP, names, hostname)
	return false
}

// corsMiddleware adds CORS headers to allow Swagger UI and other clients to access the API
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always reflect the origin, or use * if none provided
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}

		// Set CORS headers on ALL responses (including errors)
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Only set credentials header if we have a specific origin (not *)
		if origin != "*" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Handle preflight OPTIONS request immediately
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// createAuthenticator creates the appropriate authenticator based on config
func createAuthenticator(cfg *config.Config) (auth.Authenticator, error) {
	switch cfg.WebAuthMethod {
	case "basic":
		basicAuth := createBasicAuth(cfg)
		log.Printf("Web auth: basic (realm=%s, users=%d)", cfg.WebAuthRealm, len(cfg.WebAuthUsers))
		return basicAuth, nil

	case "jwt":
		jwtAuth, err := createJWTAuth(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT auth: %w", err)
		}
		log.Printf("Web auth: jwt")
		return jwtAuth, nil

	case "basic+jwt":
		basicAuth := createBasicAuth(cfg)
		jwtAuth, err := createJWTAuth(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT auth: %w", err)
		}
		chain := auth.NewChainAuthenticator(basicAuth, jwtAuth)
		log.Printf("Web auth: basic+jwt (basic first, then jwt)")
		return chain, nil

	case "jwt+basic":
		basicAuth := createBasicAuth(cfg)
		jwtAuth, err := createJWTAuth(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT auth: %w", err)
		}
		chain := auth.NewChainAuthenticator(jwtAuth, basicAuth)
		log.Printf("Web auth: jwt+basic (jwt first, then basic)")
		return chain, nil

	default:
		log.Printf("Web auth: disabled")
		return &auth.NoAuth{}, nil
	}
}

// createBasicAuth creates a basic auth authenticator from config
func createBasicAuth(cfg *config.Config) *auth.BasicAuth {
	users := make(map[string]auth.UserCredential)
	for username, user := range cfg.WebAuthUsers {
		users[username] = auth.UserCredential{
			PasswordHash: user.PasswordHash,
			Password:     user.Password,
			Roles:        user.Roles,
		}
	}
	return auth.NewBasicAuth(auth.BasicAuthConfig{
		Realm: cfg.WebAuthRealm,
		Users: users,
	})
}

// createJWTAuth creates a JWT auth authenticator from config
func createJWTAuth(cfg *config.Config) (*auth.JWTAuth, error) {
	jwtCfg := auth.JWTAuthConfig{
		Secret:       cfg.JWTSecret,
		PublicKey:    cfg.JWTPublicKey,
		JWKSAddr:     cfg.JWTJWKSAddr,
		Issuer:       cfg.JWTIssuer,
		Audience:     cfg.JWTAudience,
		ClaimUser:    cfg.JWTClaimUser,
		ClaimRole:    cfg.JWTClaimRole,
		DefaultRoles: cfg.JWTDefaultRoles,
	}

	// If no roles specified, default to Operator
	if len(jwtCfg.DefaultRoles) == 0 {
		jwtCfg.DefaultRoles = []string{"Operator"}
	}

	return auth.NewJWTAuth(jwtCfg)
}
