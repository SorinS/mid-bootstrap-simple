package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockAuthenticator is a configurable mock for testing
type mockAuthenticator struct {
	name      string
	user      *User
	err       error
	challenge string
}

func (m *mockAuthenticator) Authenticate(r *http.Request) (*User, error) {
	return m.user, m.err
}

func (m *mockAuthenticator) Challenge() string {
	return m.challenge
}

func (m *mockAuthenticator) Name() string {
	return m.name
}

func TestNewChainAuthenticator(t *testing.T) {
	auth1 := &mockAuthenticator{name: "mock1"}
	auth2 := &mockAuthenticator{name: "mock2"}

	chain := NewChainAuthenticator(auth1, auth2)

	if len(chain.authenticators) != 2 {
		t.Errorf("expected 2 authenticators, got %d", len(chain.authenticators))
	}
}

func TestChainAuthenticator_AddAuthenticator(t *testing.T) {
	chain := NewChainAuthenticator()
	auth := &mockAuthenticator{name: "mock"}

	chain.AddAuthenticator(auth)

	if len(chain.authenticators) != 1 {
		t.Errorf("expected 1 authenticator, got %d", len(chain.authenticators))
	}
}

func TestChainAuthenticator_Authenticate_FirstSucceeds(t *testing.T) {
	user := &User{Username: "test-user", Roles: []string{"admin"}}

	auth1 := &mockAuthenticator{name: "mock1", user: user}
	auth2 := &mockAuthenticator{name: "mock2", user: nil, err: fmt.Errorf("should not be called")}

	chain := NewChainAuthenticator(auth1, auth2)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result, err := chain.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected user, got nil")
	}
	if result.Username != "test-user" {
		t.Errorf("expected username 'test-user', got '%s'", result.Username)
	}
}

func TestChainAuthenticator_Authenticate_SecondSucceeds(t *testing.T) {
	user := &User{Username: "test-user", Roles: []string{"admin"}}

	// First authenticator returns nil (no credentials provided for this type)
	auth1 := &mockAuthenticator{name: "mock1", user: nil, err: nil}
	// Second authenticator succeeds
	auth2 := &mockAuthenticator{name: "mock2", user: user}

	chain := NewChainAuthenticator(auth1, auth2)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result, err := chain.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected user, got nil")
	}
	if result.Username != "test-user" {
		t.Errorf("expected username 'test-user', got '%s'", result.Username)
	}
}

func TestChainAuthenticator_Authenticate_FirstFailsSecondSucceeds(t *testing.T) {
	user := &User{Username: "test-user", Roles: []string{"admin"}}

	// First authenticator fails with error
	auth1 := &mockAuthenticator{name: "mock1", user: nil, err: fmt.Errorf("invalid credentials")}
	// Second authenticator succeeds
	auth2 := &mockAuthenticator{name: "mock2", user: user}

	chain := NewChainAuthenticator(auth1, auth2)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result, err := chain.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected user, got nil")
	}
	if result.Username != "test-user" {
		t.Errorf("expected username 'test-user', got '%s'", result.Username)
	}
}

func TestChainAuthenticator_Authenticate_AllFail(t *testing.T) {
	// Both authenticators return nil user
	auth1 := &mockAuthenticator{name: "mock1", user: nil, err: nil}
	auth2 := &mockAuthenticator{name: "mock2", user: nil, err: fmt.Errorf("invalid credentials")}

	chain := NewChainAuthenticator(auth1, auth2)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result, err := chain.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil user, got non-nil")
	}
}

func TestChainAuthenticator_Authenticate_EmptyChain(t *testing.T) {
	chain := NewChainAuthenticator()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	result, err := chain.Authenticate(req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil user, got non-nil")
	}
}

func TestChainAuthenticator_Challenge(t *testing.T) {
	auth1 := &mockAuthenticator{name: "mock1", challenge: `Basic realm="Test"`}
	auth2 := &mockAuthenticator{name: "mock2", challenge: `Bearer realm="API"`}

	chain := NewChainAuthenticator(auth1, auth2)

	challenge := chain.Challenge()

	expected := `Basic realm="Test", Bearer realm="API"`
	if challenge != expected {
		t.Errorf("expected challenge '%s', got '%s'", expected, challenge)
	}
}

func TestChainAuthenticator_Challenge_EmptyChallenges(t *testing.T) {
	auth1 := &mockAuthenticator{name: "mock1", challenge: ""}
	auth2 := &mockAuthenticator{name: "mock2", challenge: `Bearer realm="API"`}

	chain := NewChainAuthenticator(auth1, auth2)

	challenge := chain.Challenge()

	expected := `Bearer realm="API"`
	if challenge != expected {
		t.Errorf("expected challenge '%s', got '%s'", expected, challenge)
	}
}

func TestChainAuthenticator_Name(t *testing.T) {
	chain := NewChainAuthenticator()

	if chain.Name() != "chain" {
		t.Errorf("expected name 'chain', got '%s'", chain.Name())
	}
}

func TestChainAuthenticator_Authenticators(t *testing.T) {
	auth1 := &mockAuthenticator{name: "mock1"}
	auth2 := &mockAuthenticator{name: "mock2"}

	chain := NewChainAuthenticator(auth1, auth2)

	authenticators := chain.Authenticators()

	if len(authenticators) != 2 {
		t.Errorf("expected 2 authenticators, got %d", len(authenticators))
	}
}
