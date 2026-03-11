package auth

import (
	"net/http"
	"strings"
)

// ChainAuthenticator tries multiple authenticators in order.
// If any authenticator succeeds, authentication passes.
// If all authenticators fail or return nil, authentication fails.
type ChainAuthenticator struct {
	authenticators []Authenticator
}

// NewChainAuthenticator creates a new chain authenticator with the given authenticators.
// Authenticators are tried in order until one succeeds.
func NewChainAuthenticator(authenticators ...Authenticator) *ChainAuthenticator {
	return &ChainAuthenticator{
		authenticators: authenticators,
	}
}

// AddAuthenticator adds an authenticator to the chain
func (c *ChainAuthenticator) AddAuthenticator(auth Authenticator) {
	c.authenticators = append(c.authenticators, auth)
}

// Authenticate implements Authenticator interface.
// It tries each authenticator in order:
// - If an authenticator returns a user (success), authentication passes
// - If an authenticator returns an error (explicit failure), try the next one
// - If an authenticator returns nil user and nil error (no credentials), try the next one
// - If all authenticators fail, return nil (authentication required)
func (c *ChainAuthenticator) Authenticate(r *http.Request) (*User, error) {
	for _, auth := range c.authenticators {
		user, _ := auth.Authenticate(r)
		if user != nil {
			// Authentication succeeded
			return user, nil
		}
		// If err != nil, the authenticator tried but failed
		// If err == nil and user == nil, no credentials were provided for this auth type
		// Either way, try the next authenticator
	}

	// No authenticator succeeded
	return nil, nil
}

// Challenge returns a combined WWW-Authenticate header value for all authenticators
func (c *ChainAuthenticator) Challenge() string {
	var challenges []string
	for _, auth := range c.authenticators {
		if challenge := auth.Challenge(); challenge != "" {
			challenges = append(challenges, challenge)
		}
	}
	return strings.Join(challenges, ", ")
}

// Name returns the authenticator name
func (c *ChainAuthenticator) Name() string {
	return "chain"
}

// Authenticators returns the list of authenticators in the chain
func (c *ChainAuthenticator) Authenticators() []Authenticator {
	return c.authenticators
}
