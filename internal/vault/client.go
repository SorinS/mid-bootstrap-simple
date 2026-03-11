package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"mid-bootstrap-server.git/internal/config"
	"mid-bootstrap-server.git/internal/types"
)

// Client handles communication with HashiCorp Vault
type Client struct {
	config      *config.Config
	httpClient  *http.Client
	token       string
	tokenExpiry time.Time

	// Cached bootstrap token (shared across agents for token bootstrap)
	bootstrapMu    sync.RWMutex
	cachedToken    *types.BootstrapToken
	cachedTokenExp time.Time
}

// NewClient creates a new Vault client
func NewClient(cfg *config.Config) (*Client, error) {
	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.VaultSkipVerify,
	}

	// Load custom CA if provided
	if cfg.VaultCACert != "" {
		caCert, err := os.ReadFile(cfg.VaultCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read Vault CA cert: %w", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse Vault CA cert")
		}
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	client := &Client{
		config:     cfg,
		httpClient: httpClient,
	}

	// Authenticate based on method
	switch cfg.VaultAuthMethod {
	case "token":
		// Load token from file if specified
		if cfg.VaultTokenFile != "" && cfg.VaultToken == "" {
			tokenData, err := os.ReadFile(cfg.VaultTokenFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read vault token file: %w", err)
			}
			client.token = strings.TrimSpace(string(tokenData))
		} else {
			client.token = cfg.VaultToken
		}
	case "jwt":
		if err := client.authenticateJWT(); err != nil {
			return nil, fmt.Errorf("JWT authentication failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", cfg.VaultAuthMethod)
	}

	return client, nil
}

// authenticateJWT performs JWT authentication with Vault
func (c *Client) authenticateJWT() error {
	// Read JWT from file
	jwtData, err := os.ReadFile(c.config.VaultJWTFile)
	if err != nil {
		return fmt.Errorf("failed to read JWT file: %w", err)
	}
	jwt := strings.TrimSpace(string(jwtData))

	// Determine auth mount path
	authMount := c.config.VaultAuthMount
	if authMount == "" {
		authMount = "jwt"
	}

	// Build login request
	reqBody := map[string]interface{}{
		"role": c.config.VaultAuthRole,
		"jwt":  jwt,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/%s/login",
		strings.TrimSuffix(c.config.VaultAddr, "/"),
		authMount,
	)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.VaultNamespace != "" {
		req.Header.Set("X-Vault-Namespace", c.config.VaultNamespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var authResp VaultAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if authResp.Auth.ClientToken == "" {
		return fmt.Errorf("vault did not return a token")
	}

	c.token = authResp.Auth.ClientToken
	c.tokenExpiry = time.Now().Add(time.Duration(authResp.Auth.LeaseDuration) * time.Second)

	return nil
}

// ensureAuthenticated checks if token is valid and re-authenticates if needed
func (c *Client) ensureAuthenticated() error {
	// Token auth doesn't expire (or we don't track it)
	if c.config.VaultAuthMethod == "token" {
		return nil
	}

	// Check if token is about to expire (within 1 minute)
	if time.Until(c.tokenExpiry) < time.Minute {
		return c.authenticateJWT()
	}

	return nil
}

// VaultAuthResponse represents a Vault auth response
type VaultAuthResponse struct {
	Auth VaultAuthData `json:"auth"`
}

// VaultAuthData contains auth data from Vault
type VaultAuthData struct {
	ClientToken   string   `json:"client_token"`
	Accessor      string   `json:"accessor"`
	Policies      []string `json:"policies"`
	LeaseDuration int      `json:"lease_duration"`
	Renewable     bool     `json:"renewable"`
}

// GenerateBootstrapToken requests a bootstrap token from vault-secrets-mid plugin
func (c *Client) GenerateBootstrapToken(machine *types.MachineRequest) (*types.BootstrapToken, error) {
	// Ensure we have a valid token
	if err := c.ensureAuthenticated(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Build the request
	reqBody := map[string]interface{}{
		"role":     c.config.MIDRole,
		"agent_id": machine.Hostname,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make the request to Vault MID auth
	url := fmt.Sprintf("%s/v1/auth/%s/tokens/generate",
		strings.TrimSuffix(c.config.VaultAddr, "/"),
		c.config.MIDAuthMount,
	)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.token)
	if c.config.VaultNamespace != "" {
		req.Header.Set("X-Vault-Namespace", c.config.VaultNamespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var vaultResp MIDTokenResponse
	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if vaultResp.Data.Token == "" {
		return nil, fmt.Errorf("vault did not return a token")
	}

	return &types.BootstrapToken{
		Token:     vaultResp.Data.Token,
		TokenID:   vaultResp.Data.TokenID,
		AgentID:   vaultResp.Data.AgentID,
		Role:      vaultResp.Data.Role,
		ExpiresAt: vaultResp.Data.ExpiresAt,
		TTL:       vaultResp.Data.TTL,
	}, nil
}

// FetchJWTFromSource fetches a JWT from a file:// or http(s):// URL
func (c *Client) FetchJWTFromSource(source string) (string, error) {
	if strings.HasPrefix(source, "file://") {
		path := strings.TrimPrefix(source, "file://")
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to read JWT from file %s: %w", path, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequest(http.MethodGet, source, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create JWT fetch request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to fetch JWT from %s: %w", source, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("JWT source returned status %d: %s", resp.StatusCode, string(body))
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read JWT response body: %w", err)
		}

		return strings.TrimSpace(string(data)), nil
	}

	if strings.HasPrefix(source, "exec://") {
		path := strings.TrimPrefix(source, "exec://")
		cmd := exec.Command(path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("JWT exec %s failed: %w (stderr: %s)", path, err, stderr.String())
		}
		token := strings.TrimSpace(stdout.String())
		if token == "" {
			return "", fmt.Errorf("JWT exec %s returned empty output", path)
		}
		return token, nil
	}

	return "", fmt.Errorf("unsupported JWT source scheme: %s (must be file://, http://, https://, or exec://)", source)
}

// LoginWithJWTForAgent returns a cached Vault token for the agent, performing a
// fresh JWT auth login only when the cache is empty or the token has expired.
// The same token is shared across all agents bootstrapping within a TTL window.
func (c *Client) LoginWithJWTForAgent(jwtSource string, role string, agentID string) (*types.BootstrapToken, error) {
	// Check cache (read lock)
	c.bootstrapMu.RLock()
	if c.cachedToken != nil && time.Now().Before(c.cachedTokenExp) {
		token := c.cachedToken
		c.bootstrapMu.RUnlock()
		remaining := int(time.Until(c.cachedTokenExp).Seconds())
		log.Printf("Bootstrap token cache hit for %s (remaining TTL: %ds)", agentID, remaining)
		// Return a copy with the requesting agent's ID and remaining TTL
		return &types.BootstrapToken{
			Token:     token.Token,
			TokenID:   token.TokenID,
			AgentID:   agentID,
			Role:      token.Role,
			ExpiresAt: token.ExpiresAt,
			TTL:       remaining,
		}, nil
	}
	c.bootstrapMu.RUnlock()

	// Cache miss or expired — do a fresh JWT login (write lock)
	c.bootstrapMu.Lock()
	defer c.bootstrapMu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if c.cachedToken != nil && time.Now().Before(c.cachedTokenExp) {
		remaining := int(time.Until(c.cachedTokenExp).Seconds())
		return &types.BootstrapToken{
			Token:     c.cachedToken.Token,
			TokenID:   c.cachedToken.TokenID,
			AgentID:   agentID,
			Role:      c.cachedToken.Role,
			ExpiresAt: c.cachedToken.ExpiresAt,
			TTL:       remaining,
		}, nil
	}

	token, err := c.vaultJWTLogin(jwtSource, role)
	if err != nil {
		return nil, err
	}

	// Cache the token
	c.cachedToken = token
	c.cachedTokenExp = time.Now().Add(time.Duration(token.TTL) * time.Second)
	log.Printf("Bootstrap token refreshed (TTL: %ds, accessor: %s)", token.TTL, token.TokenID)

	// Return a copy with the requesting agent's ID
	return &types.BootstrapToken{
		Token:     token.Token,
		TokenID:   token.TokenID,
		AgentID:   agentID,
		Role:      token.Role,
		ExpiresAt: token.ExpiresAt,
		TTL:       token.TTL,
	}, nil
}

// vaultJWTLogin performs the actual Vault JWT auth login.
func (c *Client) vaultJWTLogin(jwtSource string, role string) (*types.BootstrapToken, error) {
	jwt, err := c.FetchJWTFromSource(jwtSource)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWT: %w", err)
	}

	authMount := c.config.VaultAuthMount
	if authMount == "" {
		authMount = "jwt"
	}

	reqBody := map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWT login request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/auth/%s/login",
		strings.TrimSuffix(c.config.VaultAddr, "/"),
		authMount,
	)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.VaultNamespace != "" {
		req.Header.Set("X-Vault-Namespace", c.config.VaultNamespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault JWT login failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault JWT login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault JWT login returned status %d: %s", resp.StatusCode, string(body))
	}

	var authResp VaultAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse vault JWT login response: %w", err)
	}

	if authResp.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault JWT login did not return a token")
	}

	expiresAt := time.Now().Add(time.Duration(authResp.Auth.LeaseDuration) * time.Second)

	return &types.BootstrapToken{
		Token:     authResp.Auth.ClientToken,
		TokenID:   authResp.Auth.Accessor,
		Role:      role,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		TTL:       authResp.Auth.LeaseDuration,
	}, nil
}

// MIDTokenResponse represents vault-secrets-mid token generate response
type MIDTokenResponse struct {
	RequestID     string       `json:"request_id"`
	LeaseID       string       `json:"lease_id"`
	LeaseDuration int          `json:"lease_duration"`
	Renewable     bool         `json:"renewable"`
	Data          MIDTokenData `json:"data"`
	Warnings      []string     `json:"warnings"`
}

// MIDTokenData contains the token data from vault-secrets-mid
type MIDTokenData struct {
	Token     string `json:"token"`
	TokenID   string `json:"token_id"`
	AgentID   string `json:"agent_id"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
	TTL       int    `json:"ttl"`
}

// VaultHealthStatus represents the health status of Vault
type VaultHealthStatus struct {
	Healthy       bool      `json:"healthy"`
	Initialized   bool      `json:"initialized"`
	Sealed        bool      `json:"sealed"`
	Standby       bool      `json:"standby"`
	Version       string    `json:"version,omitempty"`
	ClusterName   string    `json:"cluster_name,omitempty"`
	Error         string    `json:"error,omitempty"`
	LastChecked   time.Time `json:"last_checked"`
	ResponseTimeMs int64    `json:"response_time_ms"`
}

// vaultHealthResponse represents the JSON response from /v1/sys/health
type vaultHealthResponse struct {
	Initialized   bool   `json:"initialized"`
	Sealed        bool   `json:"sealed"`
	Standby       bool   `json:"standby"`
	Version       string `json:"version"`
	ClusterName   string `json:"cluster_name"`
	ClusterID     string `json:"cluster_id"`
}

// HealthCheck verifies connectivity to Vault
func (c *Client) HealthCheck() error {
	status := c.GetHealthStatus()
	if !status.Healthy {
		return fmt.Errorf("vault unhealthy: %s", status.Error)
	}
	return nil
}

// GetHealthStatus returns detailed health status of Vault
func (c *Client) GetHealthStatus() *VaultHealthStatus {
	status := &VaultHealthStatus{
		LastChecked: time.Now(),
	}

	start := time.Now()
	url := fmt.Sprintf("%s/v1/sys/health", strings.TrimSuffix(c.config.VaultAddr, "/"))

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		status.Error = fmt.Sprintf("failed to create request: %v", err)
		return status
	}

	resp, err := c.httpClient.Do(req)
	status.ResponseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		status.Error = fmt.Sprintf("failed to connect to Vault: %v", err)
		return status
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		status.Error = fmt.Sprintf("failed to read response: %v", err)
		return status
	}

	// Parse the health response
	var healthResp vaultHealthResponse
	if err := json.Unmarshal(body, &healthResp); err != nil {
		status.Error = fmt.Sprintf("failed to parse response: %v", err)
		return status
	}

	status.Initialized = healthResp.Initialized
	status.Sealed = healthResp.Sealed
	status.Standby = healthResp.Standby
	status.Version = healthResp.Version
	status.ClusterName = healthResp.ClusterName

	// Vault returns:
	// 200 for initialized+unsealed+active
	// 429 for standby node
	// 472 for DR secondary
	// 473 for performance standby
	// 501 for not initialized
	// 503 for sealed
	switch resp.StatusCode {
	case http.StatusOK, 429, 472, 473:
		status.Healthy = true
	case 501:
		status.Error = "Vault is not initialized"
	case 503:
		status.Error = "Vault is sealed"
	default:
		status.Error = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
	}

	return status
}

// ValidateToken checks if the current token is valid
func (c *Client) ValidateToken() error {
	url := fmt.Sprintf("%s/v1/auth/token/lookup-self", strings.TrimSuffix(c.config.VaultAddr, "/"))

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	if c.config.VaultNamespace != "" {
		req.Header.Set("X-Vault-Namespace", c.config.VaultNamespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token validation failed: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}
