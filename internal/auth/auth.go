package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

// User represents an authenticated user
type User struct {
	Username string
	Roles    []string
	Claims   map[string]interface{} // For JWT/OIDC claims
}

// contextKey is used for storing user in request context
type contextKey string

const userContextKey contextKey = "auth_user"

// Authenticator defines the interface for authentication providers
type Authenticator interface {
	// Authenticate checks the request and returns the authenticated user
	// Returns nil user and nil error if authentication is not provided
	// Returns nil user and error if authentication failed
	// Returns user and nil error if authentication succeeded
	Authenticate(r *http.Request) (*User, error)

	// Challenge returns the WWW-Authenticate header value for 401 responses
	Challenge() string

	// Name returns the authenticator name (e.g., "basic", "jwt", "oidc")
	Name() string
}

// jsonError writes a JSON error response
func jsonError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Middleware creates an HTTP middleware that enforces authentication
func Middleware(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := auth.Authenticate(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", auth.Challenge())
				jsonError(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if user == nil {
				w.Header().Set("WWW-Authenticate", auth.Challenge())
				jsonError(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Store user in context and continue
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MiddlewareFunc is a convenience wrapper for http.HandlerFunc
func MiddlewareFunc(auth Authenticator, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", auth.Challenge())
			jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if user == nil {
			w.Header().Set("WWW-Authenticate", auth.Challenge())
			jsonError(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// Store user in context and continue
		ctx := context.WithValue(r.Context(), userContextKey, user)
		handler(w, r.WithContext(ctx))
	}
}

// UserFromContext retrieves the authenticated user from request context
func UserFromContext(ctx context.Context) *User {
	user, ok := ctx.Value(userContextKey).(*User)
	if !ok {
		return nil
	}
	return user
}

// NoAuth is a pass-through authenticator that allows all requests
type NoAuth struct{}

func (n *NoAuth) Authenticate(r *http.Request) (*User, error) {
	return &User{Username: "anonymous"}, nil
}

func (n *NoAuth) Challenge() string {
	return ""
}

func (n *NoAuth) Name() string {
	return "none"
}
