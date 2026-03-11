package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTAuth implements JWT Bearer token authentication
type JWTAuth struct {
	config    JWTAuthConfig
	keyFunc   jwt.Keyfunc
	jwksCache *jwksCache
}

// JWTAuthConfig holds configuration for JWT authentication
type JWTAuthConfig struct {
	// Key source (pick one): Secret, PublicKey, or JWKSAddr

	// Secret is the HMAC secret for HS256/HS384/HS512 algorithms
	Secret string

	// PublicKey is the path to a PEM-encoded public key file for RS*/ES*/PS* algorithms
	PublicKey string

	// JWKSAddr is the URL to fetch JSON Web Key Set (for dynamic key retrieval)
	JWKSAddr string

	// Token validation options

	// Issuer is the expected "iss" claim (optional, skipped if empty)
	Issuer string

	// Audience is the expected "aud" claim (optional, skipped if empty)
	Audience string

	// Claim mappings

	// ClaimUser is the JWT claim to use as the username (default: "sub")
	ClaimUser string

	// ClaimRole is the JWT claim to use for the user's role (default: none, uses DefaultRoles)
	// The claim value can be a string or an array of strings
	ClaimRole string

	// DefaultRoles are the roles assigned when ClaimRole is not set or claim is missing
	// If empty, defaults to ["Operator"]
	DefaultRoles []string

	// ClockSkew is the allowed clock skew for token validation (default: 1 minute)
	ClockSkew time.Duration
}

// jwksCache caches JWKS keys with TTL
type jwksCache struct {
	mu        sync.RWMutex
	url       string
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
	client    *http.Client
}

// NewJWTAuth creates a new JWT authenticator
func NewJWTAuth(cfg JWTAuthConfig) (*JWTAuth, error) {
	j := &JWTAuth{
		config: cfg,
	}

	// Set default user claim
	if cfg.ClaimUser == "" {
		j.config.ClaimUser = "sub"
	}

	// Set default roles (used when ClaimRole is not set or claim is missing)
	if len(cfg.DefaultRoles) == 0 {
		j.config.DefaultRoles = []string{"Operator"}
	}

	// Set default clock skew
	if cfg.ClockSkew == 0 {
		j.config.ClockSkew = time.Minute
	}

	// Determine key function based on configuration
	if cfg.Secret != "" {
		// HMAC secret key
		j.keyFunc = func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(cfg.Secret), nil
		}
	} else if cfg.PublicKey != "" {
		// Load public key from file
		pemData, err := os.ReadFile(cfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key file: %w", err)
		}

		pubKey, err := parsePublicKey(pemData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		j.keyFunc = func(token *jwt.Token) (interface{}, error) {
			switch pubKey.(type) {
			case *rsa.PublicKey:
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
					}
				}
			case *ecdsa.PublicKey:
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
			}
			return pubKey, nil
		}
	} else if cfg.JWKSAddr != "" {
		// JWKS URL for dynamic key retrieval
		j.jwksCache = &jwksCache{
			url:    cfg.JWKSAddr,
			keys:   make(map[string]crypto.PublicKey),
			ttl:    15 * time.Minute,
			client: &http.Client{Timeout: 10 * time.Second},
		}

		j.keyFunc = j.jwksKeyFunc
	} else {
		return nil, fmt.Errorf("JWT auth requires secret, public_key, or jwks_addr")
	}

	return j, nil
}

// Authenticate implements Authenticator interface
func (j *JWTAuth) Authenticate(r *http.Request) (*User, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, nil // No auth provided
	}

	// Parse Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil // Not a Bearer token, let other authenticators try
	}

	tokenString := authHeader[7:]
	if tokenString == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	// Parse and validate token
	parserOpts := []jwt.ParserOption{
		jwt.WithLeeway(j.config.ClockSkew),
	}

	if j.config.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(j.config.Issuer))
	}

	if j.config.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(j.config.Audience))
	}

	token, err := jwt.Parse(tokenString, j.keyFunc, parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Get username from configured claim
	username, ok := claims[j.config.ClaimUser].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("missing or invalid '%s' claim", j.config.ClaimUser)
	}

	// Get roles from configured claim or use defaults
	roles := j.config.DefaultRoles
	if j.config.ClaimRole != "" {
		if claimRoles := j.extractRoles(claims[j.config.ClaimRole]); len(claimRoles) > 0 {
			roles = claimRoles
		}
	}

	// Build user
	user := &User{
		Username: username,
		Roles:    roles,
		Claims:   make(map[string]interface{}),
	}

	// Copy all claims to user
	for k, v := range claims {
		user.Claims[k] = v
	}

	return user, nil
}

// extractRoles extracts roles from a claim value that can be a string or []interface{}
func (j *JWTAuth) extractRoles(claimValue interface{}) []string {
	if claimValue == nil {
		return nil
	}

	// Single string role
	if role, ok := claimValue.(string); ok {
		return []string{role}
	}

	// Array of roles
	if roles, ok := claimValue.([]interface{}); ok {
		result := make([]string, 0, len(roles))
		for _, r := range roles {
			if role, ok := r.(string); ok {
				result = append(result, role)
			}
		}
		return result
	}

	return nil
}

// Challenge implements Authenticator interface
func (j *JWTAuth) Challenge() string {
	return `Bearer realm="MID Bootstrap Server"`
}

// Name implements Authenticator interface
func (j *JWTAuth) Name() string {
	return "jwt"
}

// parsePublicKey parses a PEM-encoded public key
func parsePublicKey(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// jwksKeyFunc implements key retrieval from JWKS
func (j *JWTAuth) jwksKeyFunc(token *jwt.Token) (interface{}, error) {
	// Get key ID from token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'kid' in token header")
	}

	// Try to get key from cache
	j.jwksCache.mu.RLock()
	key, exists := j.jwksCache.keys[kid]
	cacheValid := time.Since(j.jwksCache.fetchedAt) < j.jwksCache.ttl
	j.jwksCache.mu.RUnlock()

	if exists && cacheValid {
		return key, nil
	}

	// Refresh cache
	if err := j.refreshJWKS(); err != nil {
		// If we have a cached key and refresh failed, use cached
		if exists {
			return key, nil
		}
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Try again after refresh
	j.jwksCache.mu.RLock()
	key, exists = j.jwksCache.keys[kid]
	j.jwksCache.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
	}

	return key, nil
}

// refreshJWKS fetches the JWKS from the configured URL
func (j *JWTAuth) refreshJWKS() error {
	resp, err := j.jwksCache.client.Get(j.jwksCache.url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Parse keys
	keys := make(map[string]crypto.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kid == "" {
			continue
		}

		pubKey, err := parseJWK(key)
		if err != nil {
			continue // Skip invalid keys
		}

		keys[key.Kid] = pubKey
	}

	// Update cache
	j.jwksCache.mu.Lock()
	j.jwksCache.keys = keys
	j.jwksCache.fetchedAt = time.Now()
	j.jwksCache.mu.Unlock()

	return nil
}

// jwksResponse represents a JWKS response
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey represents a single JWK
type jwkKey struct {
	Kty string `json:"kty"` // Key type (RSA, EC)
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Key use (sig)
	Alg string `json:"alg"` // Algorithm

	// RSA fields
	N string `json:"n"` // Modulus
	E string `json:"e"` // Exponent

	// EC fields
	Crv string `json:"crv"` // Curve
	X   string `json:"x"`   // X coordinate
	Y   string `json:"y"`   // Y coordinate
}

// parseJWK parses a JWK into a crypto.PublicKey
func parseJWK(key jwkKey) (crypto.PublicKey, error) {
	switch key.Kty {
	case "RSA":
		return parseRSAJWK(key)
	case "EC":
		return parseECJWK(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}
}

// parseRSAJWK parses an RSA JWK
func parseRSAJWK(key jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64URLDecode(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	n := new(big.Int).SetBytes(nBytes)

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// parseECJWK parses an EC JWK
func parseECJWK(key jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64URLDecode(key.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X: %w", err)
	}

	yBytes, err := base64URLDecode(key.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y: %w", err)
	}

	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", key.Crv)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// base64URLDecode decodes a base64url-encoded string (no padding)
func base64URLDecode(s string) ([]byte, error) {
	// base64.RawURLEncoding handles URL-safe base64 without padding
	return base64.RawURLEncoding.DecodeString(s)
}
