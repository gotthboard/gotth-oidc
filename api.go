package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ProtectedAttempt is the storage-safe representation of one authorization
// attempt. State is hashed; nonce and PKCE verifier are authenticated and
// encrypted. Applications may persist these values in any storage engine.
type ProtectedAttempt struct {
	StateHash              [sha256.Size]byte
	NonceCiphertext        [protectedSecretBytes]byte
	PKCEVerifierCiphertext [protectedSecretBytes]byte
}

// Authorization contains the browser URL and opaque server-side state for one
// Authorization Code flow.
type Authorization struct {
	URL     string
	Attempt ProtectedAttempt
}

// Identity is the provider-neutral identity admitted from a verified ID token.
// It deliberately excludes authorization-shaped claims.
type Identity struct {
	Issuer      string
	Subject     string
	DisplayName string
	Email       *string
	PictureURL  *string
}

// Config defines one exact OIDC relying-party binding.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Transport    http.RoundTripper
	Entropy      io.Reader
}

// Client performs a hardened Authorization Code flow with PKCE, state, nonce,
// strict issuer checking, bounded HTTP, and no retained OAuth tokens.
type Client struct {
	provider discoveredOIDCProvider
	entropy  io.Reader
}

// New discovers and validates the configured provider. All discovered network
// endpoints must remain on the configured issuer origin.
func New(ctx context.Context, config Config) (*Client, error) {
	issuer, err := url.Parse(config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC issuer: %w", err)
	}
	provider, err := discoverOIDCProvider(ctx, config.Transport, *issuer, config.ClientID, config.ClientSecret, config.RedirectURL)
	if err != nil {
		return nil, err
	}
	entropy := config.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	return &Client{provider: provider, entropy: entropy}, nil
}

// Begin creates independent state, nonce, and PKCE material and returns the
// authorization URL plus the representation that must be persisted server-side.
func (client *Client) Begin() (Authorization, error) {
	if client == nil || client.entropy == nil {
		return Authorization{}, fmt.Errorf("OIDC client is not initialized")
	}
	material, err := generateLoginMaterial(client.entropy)
	if err != nil {
		return Authorization{}, err
	}
	protected, err := protectLoginMaterial(material, client.entropy)
	if err != nil {
		return Authorization{}, err
	}
	authorizationURL, err := client.provider.initialAuthorizationURL(material)
	if err != nil {
		return Authorization{}, err
	}
	return Authorization{
		URL: authorizationURL,
		Attempt: ProtectedAttempt{
			StateHash:              protected.stateHash,
			NonceCiphertext:        protected.nonceCiphertext,
			PKCEVerifierCiphertext: protected.pkceVerifierCiphertext,
		},
	}, nil
}

// Complete recovers a persisted one-time attempt, exchanges the authorization
// code, verifies the ID token, and returns only admitted identity claims. The
// caller remains responsible for atomically consuming the attempt before use.
func (client *Client) Complete(ctx context.Context, state, code string, attempt ProtectedAttempt) (Identity, error) {
	if client == nil {
		return Identity{}, fmt.Errorf("OIDC client is not initialized")
	}
	material, err := recoverLoginMaterial(state, attempt.StateHash[:], attempt.NonceCiphertext[:], attempt.PKCEVerifierCiphertext[:])
	if err != nil {
		return Identity{}, err
	}
	claims, err := client.provider.exchangeInitialLogin(ctx, code, material)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Issuer:      claims.issuer,
		Subject:     claims.subject,
		DisplayName: claims.displayName,
		Email:       cloneString(claims.email),
		PictureURL:  cloneString(claims.avatarURL),
	}, nil
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// Format prevents diagnostic formatting from traversing provider secrets.
func (client Client) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED OIDC CLIENT]")
}
