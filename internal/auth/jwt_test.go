package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewJWTAuth_RequiresKeySource(t *testing.T) {
	_, err := NewJWTAuth(JWTAuthConfig{})

	if err == nil {
		t.Error("expected error when no key source provided")
	}
}

func TestNewJWTAuth_WithSecret(t *testing.T) {
	jwtAuth, err := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jwtAuth == nil {
		t.Fatal("expected JWTAuth, got nil")
	}
}

func TestJWTAuth_Authenticate_NoHeader(t *testing.T) {
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user when no auth header")
	}
}

func TestJWTAuth_Authenticate_NotBearerToken(t *testing.T) {
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	user, err := jwtAuth.Authenticate(req)

	// Should return nil, nil to allow other authenticators to try
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user for non-Bearer token")
	}
}

func TestJWTAuth_Authenticate_ValidHMACToken(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "test-user" {
		t.Errorf("expected username 'test-user', got '%s'", user.Username)
	}
	if len(user.Roles) != 1 || user.Roles[0] != "Operator" {
		t.Errorf("expected default role 'Operator', got %v", user.Roles)
	}
}

func TestJWTAuth_Authenticate_CustomRoles(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret:       secret,
		DefaultRoles: []string{"Admin", "User"},
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if len(user.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(user.Roles))
	}
}

func TestJWTAuth_Authenticate_ExpiredToken(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	// Create an expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err == nil {
		t.Error("expected error for expired token")
	}
	if user != nil {
		t.Error("expected nil user for expired token")
	}
}

func TestJWTAuth_Authenticate_InvalidSignature(t *testing.T) {
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	// Create a token with a different secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("wrong-secret"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err == nil {
		t.Error("expected error for invalid signature")
	}
	if user != nil {
		t.Error("expected nil user for invalid signature")
	}
}

func TestJWTAuth_Authenticate_MissingSubClaim(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	// Create a token without 'sub' claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err == nil {
		t.Error("expected error for missing sub claim")
	}
	if user != nil {
		t.Error("expected nil user for missing sub claim")
	}
}

func TestJWTAuth_Authenticate_IssuerValidation(t *testing.T) {
	secret := "my-secret-key"

	t.Run("valid issuer", func(t *testing.T) {
		jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
			Secret: secret,
			Issuer: "my-issuer",
		})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "test-user",
			"iss": "my-issuer",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, _ := token.SignedString([]byte(secret))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		user, err := jwtAuth.Authenticate(req)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user == nil {
			t.Error("expected user, got nil")
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
			Secret: secret,
			Issuer: "my-issuer",
		})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "test-user",
			"iss": "wrong-issuer",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, _ := token.SignedString([]byte(secret))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		user, err := jwtAuth.Authenticate(req)

		if err == nil {
			t.Error("expected error for invalid issuer")
		}
		if user != nil {
			t.Error("expected nil user for invalid issuer")
		}
	})
}

func TestJWTAuth_Authenticate_AudienceValidation(t *testing.T) {
	secret := "my-secret-key"

	t.Run("valid audience", func(t *testing.T) {
		jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
			Secret:   secret,
			Audience: "my-api",
		})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "test-user",
			"aud": "my-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, _ := token.SignedString([]byte(secret))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		user, err := jwtAuth.Authenticate(req)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user == nil {
			t.Error("expected user, got nil")
		}
	})

	t.Run("invalid audience", func(t *testing.T) {
		jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
			Secret:   secret,
			Audience: "my-api",
		})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "test-user",
			"aud": "wrong-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, _ := token.SignedString([]byte(secret))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		user, err := jwtAuth.Authenticate(req)

		if err == nil {
			t.Error("expected error for invalid audience")
		}
		if user != nil {
			t.Error("expected nil user for invalid audience")
		}
	})
}

func TestJWTAuth_Authenticate_ClaimsAreCopied(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: secret,
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":          "test-user",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"custom_claim": "custom_value",
		"groups":       []string{"group1", "group2"},
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}

	// Check custom claims are copied
	if user.Claims["custom_claim"] != "custom_value" {
		t.Errorf("expected custom_claim 'custom_value', got '%v'", user.Claims["custom_claim"])
	}
	if user.Claims["sub"] != "test-user" {
		t.Errorf("expected sub claim in Claims map")
	}
}

func TestJWTAuth_Authenticate_RSAToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create JWT auth with public key
	jwtAuth := &JWTAuth{
		config: JWTAuthConfig{
			ClaimUser:    "sub",
			DefaultRoles: []string{"Operator"},
			ClockSkew:    time.Minute,
		},
	}
	jwtAuth.keyFunc = func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	}

	// Create a valid RSA-signed token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "rsa-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(privateKey)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "rsa-user" {
		t.Errorf("expected username 'rsa-user', got '%s'", user.Username)
	}
}

func TestJWTAuth_Authenticate_ECDSAToken(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Create JWT auth with public key
	jwtAuth := &JWTAuth{
		config: JWTAuthConfig{
			ClaimUser:    "sub",
			DefaultRoles: []string{"Operator"},
			ClockSkew:    time.Minute,
		},
	}
	jwtAuth.keyFunc = func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	}

	// Create a valid ECDSA-signed token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "ecdsa-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(privateKey)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "ecdsa-user" {
		t.Errorf("expected username 'ecdsa-user', got '%s'", user.Username)
	}
}

func TestJWTAuth_Challenge(t *testing.T) {
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	challenge := jwtAuth.Challenge()

	expected := `Bearer realm="MID Bootstrap Server"`
	if challenge != expected {
		t.Errorf("expected challenge '%s', got '%s'", expected, challenge)
	}
}

func TestJWTAuth_Name(t *testing.T) {
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	if jwtAuth.Name() != "jwt" {
		t.Errorf("expected name 'jwt', got '%s'", jwtAuth.Name())
	}
}

func TestJWTAuth_JWKS(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create a mock JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"alg": "RS256",
					"n":   base64URLEncode(privateKey.N.Bytes()),
					"e":   base64URLEncode([]byte{1, 0, 1}), // 65537
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	jwtAuth, err := NewJWTAuth(JWTAuthConfig{
		JWKSAddr: jwksServer.URL,
	})
	if err != nil {
		t.Fatalf("failed to create JWT auth: %v", err)
	}

	// Create a valid token with kid
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "jwks-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "test-key-id"
	tokenString, _ := token.SignedString(privateKey)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "jwks-user" {
		t.Errorf("expected username 'jwks-user', got '%s'", user.Username)
	}
}

func TestJWTAuth_EmptyBearerToken(t *testing.T) {
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret: "my-secret-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer ")

	user, err := jwtAuth.Authenticate(req)

	if err == nil {
		t.Error("expected error for empty bearer token")
	}
	if user != nil {
		t.Error("expected nil user for empty bearer token")
	}
}

func TestJWTAuth_CustomClaimUser(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret:    secret,
		ClaimUser: "email",
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "user@example.com",
		"sub":   "should-be-ignored",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "user@example.com" {
		t.Errorf("expected username 'user@example.com', got '%s'", user.Username)
	}
}

func TestJWTAuth_CustomClaimRole_SingleString(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret:    secret,
		ClaimRole: "role",
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "test-user",
		"role": "Admin",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if len(user.Roles) != 1 || user.Roles[0] != "Admin" {
		t.Errorf("expected role ['Admin'], got %v", user.Roles)
	}
}

func TestJWTAuth_CustomClaimRole_Array(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret:    secret,
		ClaimRole: "roles",
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "test-user",
		"roles": []string{"Admin", "User", "Viewer"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if len(user.Roles) != 3 {
		t.Errorf("expected 3 roles, got %d: %v", len(user.Roles), user.Roles)
	}
}

func TestJWTAuth_CustomClaimRole_MissingFallsBackToDefault(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret:       secret,
		ClaimRole:    "role",
		DefaultRoles: []string{"DefaultRole"},
	})

	// Token without 'role' claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if len(user.Roles) != 1 || user.Roles[0] != "DefaultRole" {
		t.Errorf("expected role ['DefaultRole'], got %v", user.Roles)
	}
}

func TestJWTAuth_MissingCustomUserClaim(t *testing.T) {
	secret := "my-secret-key"
	jwtAuth, _ := NewJWTAuth(JWTAuthConfig{
		Secret:    secret,
		ClaimUser: "email",
	})

	// Token without 'email' claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := jwtAuth.Authenticate(req)

	if err == nil {
		t.Error("expected error for missing email claim")
	}
	if user != nil {
		t.Error("expected nil user for missing email claim")
	}
}

// Helper function for base64url encoding
func base64URLEncode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, (len(data)*8+5)/6)
	for i := range result {
		var val uint8
		bitPos := i * 6
		bytePos := bitPos / 8
		bitOffset := bitPos % 8

		if bytePos < len(data) {
			val = data[bytePos] << bitOffset >> 2
		}
		if bitOffset > 2 && bytePos+1 < len(data) {
			val |= data[bytePos+1] >> (10 - bitOffset)
		}
		result[i] = alphabet[val&0x3f]
	}
	return string(result)
}
