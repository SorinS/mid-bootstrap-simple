package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mid-bootstrap-server.git/internal/config"
	"mid-bootstrap-server.git/internal/server"
)

var Version string
var BuildTime string

// @title MID Bootstrap Server API
// @version 0.4.3
// @description API for MAG (MID Agent) bootstrap operations and management.
// @description This server handles agent enrollment, bootstrap token generation, and approval workflows.

// @contact.name MAG Support
// @contact.url https://github.com/your-org/mid-bootstrap-server

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @BasePath /

// @securityDefinitions.basic BasicAuth
// @description HTTP Basic Authentication. Click "Authorize" button and enter username/password configured in the server.

// @tag.name Bootstrap
// @tag.description Agent bootstrap endpoints (no auth required)
// @tag.name Admin
// @tag.description Administrative endpoints (auth required)
// @tag.name System
// @tag.description System and agent management endpoints

func main() {
	showVersion := flag.Bool("v", false, "Show version")
	configPath := flag.String("config", "", "Path to configuration file (recommended)")

	// Start with defaults, then layer config file, then CLI flags
	cfg := config.DefaultConfig()

	// Server settings
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "Listen address")
	flag.BoolVar(&cfg.UseTLS, "use-tls", cfg.UseTLS, "Enable TLS (set to false when behind a reverse proxy)")
	flag.StringVar(&cfg.TLSCert, "tls-cert", cfg.TLSCert, "Path to TLS certificate file")
	flag.StringVar(&cfg.TLSKey, "tls-key", cfg.TLSKey, "Path to TLS private key file")
	flag.StringVar(&cfg.TLSMinVersion, "tls-min-version", cfg.TLSMinVersion, "Minimum TLS version: 1.2 or 1.3")

	// Vault connection settings
	flag.StringVar(&cfg.VaultAddr, "vault-addr", cfg.VaultAddr, "Vault server address")
	flag.BoolVar(&cfg.VaultUseTLS, "vault-use-tls", cfg.VaultUseTLS, "Enable TLS for Vault connection")
	flag.StringVar(&cfg.VaultCACert, "vault-ca-cert", cfg.VaultCACert, "Path to Vault CA certificate")
	flag.BoolVar(&cfg.VaultSkipVerify, "vault-skip-verify", cfg.VaultSkipVerify, "Skip TLS verification for Vault")
	flag.StringVar(&cfg.VaultNamespace, "vault-namespace", cfg.VaultNamespace, "Vault namespace (enterprise)")

	// Vault authentication settings
	flag.StringVar(&cfg.VaultAuthMethod, "vault-auth-method", cfg.VaultAuthMethod, "Vault auth method: token or jwt")
	flag.StringVar(&cfg.VaultToken, "vault-token", cfg.VaultToken, "Vault token (for token auth)")
	flag.StringVar(&cfg.VaultTokenFile, "vault-token-file", cfg.VaultTokenFile, "Path to Vault token file (for token auth)")
	flag.StringVar(&cfg.VaultAuthRole, "vault-auth-role", cfg.VaultAuthRole, "Vault auth role (required for jwt auth)")
	flag.StringVar(&cfg.VaultAuthMount, "vault-auth-mount", cfg.VaultAuthMount, "Vault auth mount path (default: jwt)")
	flag.StringVar(&cfg.VaultJWTFile, "vault-jwt-file", cfg.VaultJWTFile, "Path to JWT file (for jwt auth)")

	// MID auth settings
	flag.StringVar(&cfg.MIDAuthMount, "mid-auth-mount", cfg.MIDAuthMount, "Vault MID auth mount path")
	flag.StringVar(&cfg.MIDRole, "mid-role", cfg.MIDRole, "Vault MID role for token generation")

	// Bootstrap mode settings
	flag.StringVar(&cfg.BootstrapType, "bootstrap-type", cfg.BootstrapType, "Bootstrap type: certificate (default) or token")
	flag.StringVar(&cfg.VaultJWTSource, "vault-jwt-source", cfg.VaultJWTSource, "JWT source for token bootstrap: file:///path or http://host/path")

	// Request handling
	flag.IntVar(&cfg.DefaultRetryAfter, "default-retry-after", cfg.DefaultRetryAfter, "Seconds to suggest for retry")

	// Security settings
	flag.BoolVar(&cfg.RequireTPM, "require-tpm", cfg.RequireTPM, "Require TPM attestation")
	flag.BoolVar(&cfg.AutoApproveFromTrust, "auto-approve-trust", cfg.AutoApproveFromTrust, "Auto-approve from trusted networks")
	flag.BoolVar(&cfg.AutoApproveTPM, "auto-approve-tpm", cfg.AutoApproveTPM, "Auto-approve when TPM attestation is verified")
	flag.BoolVar(&cfg.AutoApproveDNS, "auto-approve-dns", cfg.AutoApproveDNS, "Auto-approve when reverse DNS matches hostname")

	// Web UI settings
	flag.BoolVar(&cfg.WebEnabled, "web-enabled", cfg.WebEnabled, "Enable web UI")
	flag.StringVar(&cfg.WebPathPrefix, "web-path-prefix", cfg.WebPathPrefix, "Web UI path prefix")
	flag.StringVar(&cfg.SessionSecret, "session-secret", cfg.SessionSecret, "Session secret for web cookies")
	flag.StringVar(&cfg.WebAuthMethod, "web-auth-method", cfg.WebAuthMethod, "Web auth method: none, basic, jwt, basic+jwt, jwt+basic")
	flag.StringVar(&cfg.WebAuthRealm, "web-auth-realm", cfg.WebAuthRealm, "Realm for basic auth")

	// JWT authentication settings
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", cfg.JWTSecret, "HMAC secret for JWT auth")
	flag.StringVar(&cfg.JWTPublicKey, "jwt-public-key", cfg.JWTPublicKey, "Path to PEM public key for JWT auth")
	flag.StringVar(&cfg.JWTJWKSAddr, "jwt-jwks-addr", cfg.JWTJWKSAddr, "URL to JWKS endpoint for JWT auth")
	flag.StringVar(&cfg.JWTIssuer, "jwt-issuer", cfg.JWTIssuer, "Expected JWT issuer claim")
	flag.StringVar(&cfg.JWTAudience, "jwt-audience", cfg.JWTAudience, "Expected JWT audience claim")
	flag.StringVar(&cfg.JWTClaimUser, "jwt-claim-user", cfg.JWTClaimUser, "JWT claim for username (default: sub)")
	flag.StringVar(&cfg.JWTClaimRole, "jwt-claim-role", cfg.JWTClaimRole, "JWT claim for role")

	// Storage settings
	flag.StringVar(&cfg.StoreType, "store-type", cfg.StoreType, "Store type: memory or sqlite")
	flag.StringVar(&cfg.StorePath, "store-path", cfg.StorePath, "Path to SQLite database file")

	// Registration mTLS settings
	flag.BoolVar(&cfg.RegistrationRequireMTLS, "registration-require-mtls", cfg.RegistrationRequireMTLS, "Require client certificate for /registration")
	flag.StringVar(&cfg.RegistrationCACert, "registration-ca-cert", cfg.RegistrationCACert, "Path to CA cert for verifying registration client certs")

	// Alert settings
	flag.IntVar(&cfg.AlertStaleAgentMinutes, "alert-stale-agent-minutes", cfg.AlertStaleAgentMinutes, "Minutes before agent is considered stale")
	flag.IntVar(&cfg.AlertCheckInterval, "alert-check-interval", cfg.AlertCheckInterval, "Interval in seconds to check for stale agents")

	// vSphere integration settings
	flag.StringVar(&cfg.VSphereAddr, "vsphere-addr", cfg.VSphereAddr, "vCenter address (enables vSphere integration)")
	flag.StringVar(&cfg.VSphereUsername, "vsphere-username", cfg.VSphereUsername, "vCenter username")
	flag.StringVar(&cfg.VSpherePasswordFile, "vsphere-password-file", cfg.VSpherePasswordFile, "Path to vCenter password file")
	flag.StringVar(&cfg.VSphereDatacenter, "vsphere-datacenter", cfg.VSphereDatacenter, "vSphere datacenter to search")
	flag.BoolVar(&cfg.VSphereSkipVerify, "vsphere-skip-verify", cfg.VSphereSkipVerify, "Skip TLS verification for vCenter")
	flag.BoolVar(&cfg.VSphereEKBinding, "vsphere-ek-binding", cfg.VSphereEKBinding, "Enable vTPM EK fingerprint verification")
	flag.BoolVar(&cfg.VSphereRequireEK, "vsphere-require-ek", cfg.VSphereRequireEK, "Fail attestation if EK data unavailable from vSphere")

	flag.Parse()

	if *showVersion {
		fmt.Printf("MID Bootstrap Server Version: %s, build: %s\n", Version, BuildTime)
		return
	}

	// If a config file is specified, load it over defaults, then re-apply
	// only the flags that were explicitly set on the command line.
	if *configPath != "" {
		fileCfg, err := config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		// Start from the file config
		*cfg = *fileCfg

		// Re-apply only explicitly provided CLI flags on top
		flag.Visit(func(f *flag.Flag) {
			f.Value.Set(f.Value.String())
		})
	}

	// Check environment variables as fallback
	if v := os.Getenv("VAULT_ADDR"); v != "" && cfg.VaultAddr == "" {
		cfg.VaultAddr = v
	}
	if v := os.Getenv("VAULT_TOKEN"); v != "" && cfg.VaultToken == "" {
		cfg.VaultToken = v
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	log.Printf("Starting MID Bootstrap Server")
	log.Printf("  Listen: %s", cfg.ListenAddr)
	if cfg.UseTLS {
		log.Printf("  TLS: enabled (cert=%s, key=%s)", cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Printf("  TLS: disabled (plain HTTP, reverse proxy mode)")
	}
	log.Printf("  Vault: %s (TLS: %v)", cfg.VaultAddr, cfg.VaultUseTLS)
	log.Printf("  Vault Auth: %s", cfg.VaultAuthMethod)
	if cfg.VaultAuthMethod == "jwt" {
		log.Printf("  Vault Auth Role: %s", cfg.VaultAuthRole)
	}
	log.Printf("  Bootstrap Type: %s", cfg.BootstrapType)
	if cfg.BootstrapType == "token" {
		log.Printf("  JWT Source: %s", cfg.VaultJWTSource)
	} else {
		log.Printf("  MID Auth Mount: %s", cfg.MIDAuthMount)
		log.Printf("  MID Role: %s", cfg.MIDRole)
	}
	log.Printf("  Web UI: %v", cfg.WebEnabled)
	if cfg.VSphereAddr != "" {
		log.Printf("  vSphere: %s (EK binding: %v, require EK: %v)", cfg.VSphereAddr, cfg.VSphereEKBinding, cfg.VSphereRequireEK)
	}

	// Create server
	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigCh
	log.Println("Shutting down...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
