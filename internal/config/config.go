package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all server configuration
type Config struct {
	// Server settings
	ListenAddr    string `json:"listen_addr"`    // e.g., ":8443"
	TLSCert       string `json:"tls_cert"`       // Path to TLS certificate
	TLSKey        string `json:"tls_key"`        // Path to TLS private key
	TLSMinVersion string `json:"tls_min_version"` // Minimum TLS version: "1.2" or "1.3"

	// Vault connection settings
	VaultAddr       string `json:"vault_addr"`                  // e.g., "https://vault:8200"
	VaultCACert     string `json:"vault_ca_cert,omitempty"`     // Path to Vault CA cert
	VaultSkipVerify bool   `json:"vault_skip_verify,omitempty"` // Skip TLS verification
	VaultNamespace  string `json:"vault_namespace,omitempty"`   // Vault namespace (enterprise)

	// Vault authentication settings
	VaultAuthMethod string `json:"vault_auth_method"`           // Auth method: "token" or "jwt"
	VaultAuthRole   string `json:"vault_auth_role,omitempty"`   // Role for JWT auth (required for jwt)
	VaultAuthMount  string `json:"vault_auth_mount,omitempty"`  // Auth mount path (default: "jwt" for jwt auth)
	VaultToken      string `json:"vault_token,omitempty"`       // Static token (for token auth)
	VaultTokenFile  string `json:"vault_token_file,omitempty"`  // Path to token file (for token auth)
	VaultJWTFile    string `json:"vault_jwt_file,omitempty"`    // Path to JWT file (for jwt auth)

	// Vault MID auth settings (for generating bootstrap tokens - used when bootstrap_type is "certificate")
	MIDAuthMount string `json:"mid_auth_mount"` // MID auth mount path (e.g., "mid")
	MIDRole      string `json:"mid_role"`       // MID role for token generation (e.g., "vm")

	// Bootstrap mode settings
	BootstrapType  string `json:"bootstrap_type,omitempty"`   // "certificate" (default, MID auth) or "token" (Vault JWT login)
	VaultJWTSource string `json:"vault_jwt_source,omitempty"` // URL for JWT: "file:///path/to/jwt" or "http://host:port/path"

	// Vault health check settings
	VaultHealthCheckInterval time.Duration `json:"vault_health_check_interval,omitempty"` // How often to check Vault health (default: 20s, 0 to disable)

	// Request handling
	RequestTTL         time.Duration `json:"request_ttl"`          // How long to keep pending requests
	CleanupInterval    time.Duration `json:"cleanup_interval"`     // How often to clean expired requests
	DefaultRetryAfter  int           `json:"default_retry_after"`  // Seconds to suggest for retry

	// Security settings
	TrustedNetworks      []string `json:"trusted_networks,omitempty"`       // CIDRs to auto-approve
	RequireTPM           bool     `json:"require_tpm,omitempty"`            // Require TPM attestation
	AutoApproveFromTrust bool     `json:"auto_approve_from_trust,omitempty"` // Auto-approve trusted networks
	AutoApproveTPM       bool     `json:"auto_approve_tpm,omitempty"`       // Auto-approve when TPM attestation is verified
	AutoApproveDNS       bool     `json:"auto_approve_dns,omitempty"`       // Auto-approve when reverse DNS matches hostname

	// Provisioning windows (optional)
	ProvisioningWindows []ProvisioningWindowConfig `json:"provisioning_windows,omitempty"`

	// Web UI settings
	WebEnabled    bool   `json:"web_enabled"`
	WebPathPrefix string `json:"web_path_prefix"` // e.g., "/admin"
	SessionSecret string `json:"session_secret"`  // For web session cookies

	// Web authentication settings
	// WebAuthMethod controls how web UI auth works:
	// - "none": No authentication (anonymous access)
	// - "basic": HTTP Basic authentication only
	// - "jwt": JWT Bearer token authentication only
	// - "basic+jwt" or "jwt+basic": Chain of authenticators (try both, first success wins)
	WebAuthMethod string                 `json:"web_auth_method"` // "none", "basic", "jwt", "basic+jwt", "jwt+basic"
	WebAuthRealm  string                 `json:"web_auth_realm"`  // Realm for basic auth
	WebAuthUsers  map[string]WebAuthUser `json:"web_auth_users"`  // Users for basic auth

	// JWT authentication settings (used when web_auth_method includes "jwt")
	// Key source (pick one): jwt_secret, jwt_public_key, or jwt_jwks_addr
	JWTSecret     string `json:"jwt_secret,omitempty"`      // HMAC secret for HS256/HS384/HS512
	JWTPublicKey  string `json:"jwt_public_key,omitempty"`  // Path to PEM public key file for RS*/ES*/PS*
	JWTJWKSAddr   string `json:"jwt_jwks_addr,omitempty"`   // URL to JWKS endpoint for dynamic key retrieval
	// Token validation
	JWTIssuer       string   `json:"jwt_issuer,omitempty"`        // Expected "iss" claim (optional)
	JWTAudience     string   `json:"jwt_audience,omitempty"`      // Expected "aud" claim (optional)
	JWTClaimUser    string   `json:"jwt_claim_user,omitempty"`    // JWT claim for username (default: "sub")
	JWTClaimRole    string   `json:"jwt_claim_role,omitempty"`    // JWT claim for role (default: uses jwt_default_roles)
	JWTDefaultRoles []string `json:"jwt_default_roles,omitempty"` // Fallback roles when jwt_claim_role is not set or missing

	// Storage settings
	StoreType string `json:"store_type"` // "memory" or "sqlite"
	StorePath string `json:"store_path"` // Path to SQLite database file (for sqlite type)

	// Registration mTLS settings
	RegistrationRequireMTLS bool   `json:"registration_require_mtls,omitempty"` // Require client certificate for /registration
	RegistrationCACert      string `json:"registration_ca_cert,omitempty"`      // Path to CA cert for verifying client certs

	// Alert settings
	AlertStaleAgentMinutes int `json:"alert_stale_agent_minutes,omitempty"` // Minutes before agent is considered stale (default: 10)
	AlertCheckInterval     int `json:"alert_check_interval,omitempty"`      // Interval in seconds to check for stale agents (default: 60)
}

// WebAuthUser holds credentials for a web admin user
type WebAuthUser struct {
	PasswordHash string   `json:"password_hash,omitempty"` // bcrypt hash (preferred)
	Password     string   `json:"password,omitempty"`      // plaintext (not recommended)
	Roles        []string `json:"roles,omitempty"`         // e.g., ["admin", "viewer"]
}

// ProvisioningWindowConfig defines a time window for provisioning
type ProvisioningWindowConfig struct {
	Start    string   `json:"start"`    // e.g., "09:00"
	End      string   `json:"end"`      // e.g., "17:00"
	Timezone string   `json:"timezone"` // e.g., "America/New_York"
	Days     []string `json:"days"`     // e.g., ["Monday", "Tuesday", ...]
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:               ":8443",
		TLSMinVersion:            "1.2",
		VaultAddr:                "http://127.0.0.1:8200",
		VaultAuthMethod:          "token",
		MIDAuthMount:             "mid",
		MIDRole:                  "vm",
		BootstrapType:            "certificate",
		VaultHealthCheckInterval: 20 * time.Second,
		RequestTTL:               24 * time.Hour,
		CleanupInterval:          1 * time.Hour,
		DefaultRetryAfter:        300, // 5 minutes
		WebEnabled:               true,
		WebPathPrefix:            "/admin",
		SessionSecret:            "change-me-in-production",
		WebAuthMethod:            "none",
		WebAuthRealm:             "MID Bootstrap Server",
		StoreType:                "memory",
		StorePath:                "bootstrap.db",
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for required fields
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.VaultAddr == "" {
		return fmt.Errorf("vault_addr is required")
	}
	// Validate bootstrap type
	if c.BootstrapType != "" && c.BootstrapType != "certificate" && c.BootstrapType != "token" {
		return fmt.Errorf("bootstrap_type must be 'certificate' or 'token'")
	}

	// MID auth settings only required for certificate bootstrap type
	if c.BootstrapType != "token" {
		if c.MIDAuthMount == "" {
			return fmt.Errorf("mid_auth_mount is required when bootstrap_type is 'certificate'")
		}
		if c.MIDRole == "" {
			return fmt.Errorf("mid_role is required when bootstrap_type is 'certificate'")
		}
	}

	// Token bootstrap requires JWT source and auth settings
	if c.BootstrapType == "token" {
		if c.VaultJWTSource == "" {
			return fmt.Errorf("vault_jwt_source is required when bootstrap_type is 'token'")
		}
		if !strings.HasPrefix(c.VaultJWTSource, "file://") && !strings.HasPrefix(c.VaultJWTSource, "http://") && !strings.HasPrefix(c.VaultJWTSource, "https://") && !strings.HasPrefix(c.VaultJWTSource, "exec://") {
			return fmt.Errorf("vault_jwt_source must start with 'file://', 'http://', 'https://', or 'exec://'")
		}
		if c.VaultAuthRole == "" {
			return fmt.Errorf("vault_auth_role is required when bootstrap_type is 'token'")
		}
	}

	// Validate TLS settings
	if c.TLSMinVersion != "" && c.TLSMinVersion != "1.2" && c.TLSMinVersion != "1.3" {
		return fmt.Errorf("tls_min_version must be '1.2' or '1.3'")
	}

	// Validate Vault auth method
	if c.VaultAuthMethod != "token" && c.VaultAuthMethod != "jwt" {
		return fmt.Errorf("vault_auth_method must be 'token' or 'jwt'")
	}

	// Token auth requires token or token file
	if c.VaultAuthMethod == "token" {
		if c.VaultToken == "" && c.VaultTokenFile == "" {
			return fmt.Errorf("vault_token or vault_token_file is required when vault_auth_method is 'token'")
		}
	}

	// JWT auth requires role and jwt file
	if c.VaultAuthMethod == "jwt" {
		if c.VaultAuthRole == "" {
			return fmt.Errorf("vault_auth_role is required when vault_auth_method is 'jwt'")
		}
		if c.VaultJWTFile == "" {
			return fmt.Errorf("vault_jwt_file is required when vault_auth_method is 'jwt'")
		}
	}

	// Validate web auth method
	validWebAuth := map[string]bool{
		"none":      true,
		"basic":     true,
		"jwt":       true,
		"basic+jwt": true,
		"jwt+basic": true,
		"":          true,
	}
	if !validWebAuth[c.WebAuthMethod] {
		return fmt.Errorf("web_auth_method must be 'none', 'basic', 'jwt', 'basic+jwt', or 'jwt+basic'")
	}

	// Basic auth requires at least one user (when basic is used)
	needsBasic := c.WebAuthMethod == "basic" || c.WebAuthMethod == "basic+jwt" || c.WebAuthMethod == "jwt+basic"
	if needsBasic && len(c.WebAuthUsers) == 0 {
		return fmt.Errorf("web_auth_users is required when web_auth_method includes 'basic'")
	}

	// JWT auth requires at least one key source (when jwt is used)
	needsJWT := c.WebAuthMethod == "jwt" || c.WebAuthMethod == "basic+jwt" || c.WebAuthMethod == "jwt+basic"
	if needsJWT {
		if c.JWTSecret == "" && c.JWTPublicKey == "" && c.JWTJWKSAddr == "" {
			return fmt.Errorf("jwt_secret, jwt_public_key, or jwt_jwks_addr is required when web_auth_method includes 'jwt'")
		}
	}

	// Validate store type
	if c.StoreType != "" && c.StoreType != "memory" && c.StoreType != "sqlite" {
		return fmt.Errorf("store_type must be 'memory' or 'sqlite'")
	}

	// SQLite requires a path
	if c.StoreType == "sqlite" && c.StorePath == "" {
		return fmt.Errorf("store_path is required when store_type is 'sqlite'")
	}

	// mTLS for registration requires CA cert
	if c.RegistrationRequireMTLS && c.RegistrationCACert == "" {
		return fmt.Errorf("registration_ca_cert is required when registration_require_mtls is true")
	}

	return nil
}
