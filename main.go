package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mid-bootstrap-server.git/internal/config"
	"mid-bootstrap-server.git/internal/server"
)

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
	// Parse command line flags
	configPath := flag.String("config", "", "Path to configuration file (recommended)")
	listenAddr := flag.String("listen", ":8443", "Listen address")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file")
	vaultAddr := flag.String("vault-addr", "", "Vault server address")
	vaultAuthMethod := flag.String("vault-auth-method", "token", "Vault auth method: token or jwt")
	vaultToken := flag.String("vault-token", "", "Vault token (for token auth)")
	vaultAuthRole := flag.String("vault-auth-role", "", "Vault auth role (required for jwt auth)")
	vaultAuthMount := flag.String("vault-auth-mount", "", "Vault auth mount path (default: jwt for jwt auth)")
	midAuthMount := flag.String("mid-auth-mount", "mid", "Vault MID auth mount path")
	midRole := flag.String("mid-role", "vm", "Vault MID role for token generation")
	bootstrapType := flag.String("bootstrap-type", "", "Bootstrap type: certificate (default, MID auth) or token (Vault JWT login)")
	vaultJWTSource := flag.String("vault-jwt-source", "", "JWT source URL for token bootstrap: file:///path or http://host:port/path")
	flag.Parse()

	var cfg *config.Config
	var err error

	// Load configuration
	if *configPath != "" {
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		// CLI flags override config file
		if *listenAddr != ":8443" {
			cfg.ListenAddr = *listenAddr
		}
		if *tlsCert != "" {
			cfg.TLSCert = *tlsCert
		}
		if *tlsKey != "" {
			cfg.TLSKey = *tlsKey
		}
		if *bootstrapType != "" {
			cfg.BootstrapType = *bootstrapType
		}
		if *vaultJWTSource != "" {
			cfg.VaultJWTSource = *vaultJWTSource
		}
	} else {
		// Use command line flags and defaults
		cfg = config.DefaultConfig()
		cfg.ListenAddr = *listenAddr
		cfg.TLSCert = *tlsCert
		cfg.TLSKey = *tlsKey
		if *vaultAddr != "" {
			cfg.VaultAddr = *vaultAddr
		}
		cfg.VaultAuthMethod = *vaultAuthMethod
		if *vaultToken != "" {
			cfg.VaultToken = *vaultToken
		}
		if *vaultAuthRole != "" {
			cfg.VaultAuthRole = *vaultAuthRole
		}
		if *vaultAuthMount != "" {
			cfg.VaultAuthMount = *vaultAuthMount
		}
		cfg.MIDAuthMount = *midAuthMount
		cfg.MIDRole = *midRole
		if *bootstrapType != "" {
			cfg.BootstrapType = *bootstrapType
		}
		if *vaultJWTSource != "" {
			cfg.VaultJWTSource = *vaultJWTSource
		}

		// Check environment variables
		if v := os.Getenv("VAULT_ADDR"); v != "" && cfg.VaultAddr == "" {
			cfg.VaultAddr = v
		}
		if v := os.Getenv("VAULT_TOKEN"); v != "" && cfg.VaultToken == "" {
			cfg.VaultToken = v
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	log.Printf("Starting MID Bootstrap Server")
	log.Printf("  Listen: %s", cfg.ListenAddr)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("  TLS: enabled (cert=%s, key=%s)", cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Printf("  TLS: disabled (plain HTTP)")
	}
	log.Printf("  Vault: %s", cfg.VaultAddr)
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
