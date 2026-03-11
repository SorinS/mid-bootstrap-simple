package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// BasicAuth implements HTTP Basic Authentication
type BasicAuth struct {
	realm string
	users map[string]UserCredential
}

// UserCredential holds user credentials for basic auth
type UserCredential struct {
	// PasswordHash is SHA-256 hash of the password (hex encoded)
	PasswordHash string
	// Password is plaintext password (for simple setups)
	Password string
	// Roles assigned to this user
	Roles []string
}

// BasicAuthConfig holds configuration for basic auth
type BasicAuthConfig struct {
	Realm string
	Users map[string]UserCredential
}

// NewBasicAuth creates a new basic auth authenticator
func NewBasicAuth(cfg BasicAuthConfig) *BasicAuth {
	realm := cfg.Realm
	if realm == "" {
		realm = "MID Bootstrap Server"
	}
	return &BasicAuth{
		realm: realm,
		users: cfg.Users,
	}
}

// Authenticate implements Authenticator interface
func (b *BasicAuth) Authenticate(r *http.Request) (*User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, nil // No auth provided
	}

	// Parse Basic auth header
	if !strings.HasPrefix(authHeader, "Basic ") {
		return nil, fmt.Errorf("invalid authorization header")
	}

	decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding")
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid credentials format")
	}

	username := parts[0]
	password := parts[1]

	// Look up user
	cred, exists := b.users[username]
	if !exists {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if !b.verifyPassword(password, cred) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return &User{
		Username: username,
		Roles:    cred.Roles,
	}, nil
}

// verifyPassword checks if the provided password matches the stored credential
func (b *BasicAuth) verifyPassword(password string, cred UserCredential) bool {
	// Try SHA-256 hash first
	if cred.PasswordHash != "" {
		inputHash := HashPassword(password)
		return secureCompare(inputHash, cred.PasswordHash)
	}

	// Fall back to plaintext comparison (constant time)
	if cred.Password != "" {
		return secureCompare(password, cred.Password)
	}

	return false
}

// secureCompare performs constant-time string comparison
func secureCompare(a, b string) bool {
	// Use SHA-256 to normalize length for constant-time compare
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// Challenge implements Authenticator interface
func (b *BasicAuth) Challenge() string {
	return fmt.Sprintf(`Basic realm="%s"`, b.realm)
}

// Name implements Authenticator interface
func (b *BasicAuth) Name() string {
	return "basic"
}

// HashPassword creates a SHA-256 hash of a password (hex encoded)
// Use this to generate password hashes for config:
//
//	echo -n "mypassword" | sha256sum
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}
