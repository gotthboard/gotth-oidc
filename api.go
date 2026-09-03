package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProtectedAttempt is the storage-safe representation of one authorization
// attempt. State is hashed; nonce and PKCE verifier are authenticated and
// encrypted. Applications may persist these values in any storage engine.
type ProtectedAttempt struct {
	StateHash              [sha256.Size]byte
	NonceCiphertext        [protectedSecretBytes]byte
	PKCEVerifierCiphertext [protectedSecretBytes]byte
	ContextCiphertext      string
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

// TokenSet is returned only by explicit token-bearing APIs. Consumers assume
// responsibility for encryption at rest, rotation, revocation, and disclosure.
type TokenSet struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	IDToken      string
	Scope        []string
	ExpiresAt    time.Time
}

// Completion combines verified identity with explicitly requested tokens.
type Completion struct {
	Identity Identity
	Tokens   TokenSet
}

// Config defines one exact OIDC relying-party binding.
type Config struct {
	IssuerURL                          string
	ClientID                           string
	ClientSecret                       string
	RedirectURL                        string
	Transport                          http.RoundTripper
	Entropy                            io.Reader
	Clock                              func() time.Time
	EndpointPolicy                     EndpointPolicy
	AllowInsecureLoopback              bool
	TrustedAudiences                   []string
	IdentityPolicy                     IdentityPolicy
	RequireAuthorizationResponseIssuer bool
	ClientAuthentication               ClientAuthentication
	RequestObjectSigner                JWTSigner
	TokenDecrypter                     JWTDecrypter
	EnableJARM                         bool
	EnablePAR                          bool
	EnableMutualTLS                    bool
	DPoPSigner                         JWTSigner
}

// Client performs a hardened Authorization Code flow with PKCE, state, nonce,
// strict issuer checking, bounded HTTP, and no retained OAuth tokens.
type Client struct {
	provider              discoveredOIDCProvider
	entropy               io.Reader
	clock                 func() time.Time
	identityPolicy        IdentityPolicy
	requireResponseIssuer bool
}

// New discovers and validates the configured provider. All discovered network
// endpoints must remain on the configured issuer origin.
func New(ctx context.Context, config Config) (*Client, error) {
	issuer, err := url.Parse(config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC issuer: %w", err)
	}
	provider, err := discoverOIDCProviderWithConfig(ctx, config.Transport, *issuer, config)
	if err != nil {
		return nil, err
	}
	entropy := config.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Client{provider: provider, entropy: entropy, clock: clock, identityPolicy: config.IdentityPolicy, requireResponseIssuer: config.RequireAuthorizationResponseIssuer}, nil
}

// Begin creates independent state, nonce, and PKCE material and returns the
// authorization URL plus the representation that must be persisted server-side.
func (client *Client) Begin() (Authorization, error) {
	return client.BeginContext(context.Background(), AuthorizationOptions{})
}

// BeginContext creates an authorization request with bounded optional OpenID
// Connect parameters. Network I/O occurs only when PAR is selected.
func (client *Client) BeginContext(ctx context.Context, options AuthorizationOptions) (Authorization, error) {
	if client == nil || client.entropy == nil || client.clock == nil {
		return Authorization{}, fmt.Errorf("OIDC client is not initialized")
	}
	if ctx == nil {
		return Authorization{}, fmt.Errorf("OIDC authorization context is required")
	}
	validated, err := validateAuthorizationOptions(options, client.identityPolicy)
	if err != nil {
		return Authorization{}, err
	}
	material, err := generateLoginMaterial(client.entropy)
	if err != nil {
		return Authorization{}, err
	}
	protected, err := protectLoginMaterial(material, client.entropy)
	if err != nil {
		return Authorization{}, err
	}
	now := client.clock().UTC()
	contextEnvelope, err := sealAttemptContext(material.state, protected.stateHash, attemptContext{
		Version: attemptContextVersion, Issuer: client.provider.issuer,
		ClientID: client.provider.oauth2Config.ClientID, RedirectURL: client.provider.oauth2Config.RedirectURL,
		ResponseMode: validated.responseMode, RequireResponseIssuer: client.requireResponseIssuer,
		StartedAtUnix: now.Unix(), MaxAgeSeconds: validated.maxAgeSeconds,
		ACRValues: append([]string(nil), validated.acrValues...), UseUserInfo: validated.useUserInfo,
		RequireName: validated.requireName, RequireEmail: validated.requireEmail,
		OfflineAccess: validated.offlineAccess,
	})
	if err != nil {
		return Authorization{}, err
	}
	authorizationURL, err := client.provider.initialAuthorizationURLWithOptions(ctx, material, validated, now)
	if err != nil {
		return Authorization{}, err
	}
	return Authorization{
		URL: authorizationURL,
		Attempt: ProtectedAttempt{
			StateHash:              protected.stateHash,
			NonceCiphertext:        protected.nonceCiphertext,
			PKCEVerifierCiphertext: protected.pkceVerifierCiphertext,
			ContextCiphertext:      base64.RawURLEncoding.EncodeToString(contextEnvelope),
		},
	}, nil
}

// Complete recovers a persisted one-time attempt, exchanges the authorization
// code, verifies the ID token, and returns only admitted identity claims. The
// caller remains responsible for atomically consuming the attempt before use.
func (client *Client) Complete(ctx context.Context, state, code string, attempt ProtectedAttempt) (Identity, error) {
	return client.CompleteResponse(ctx, AuthorizationResponse{State: state, Code: code, Mode: ResponseModeQuery}, attempt)
}

// CompleteResponse validates a parsed authorization response against its
// authenticated attempt and returns identity without returning OAuth tokens.
func (client *Client) CompleteResponse(ctx context.Context, response AuthorizationResponse, attempt ProtectedAttempt) (Identity, error) {
	completion, err := client.complete(ctx, response, attempt, false)
	return completion.Identity, err
}

// CompleteTokens is the explicit token-bearing completion path. The default
// Complete and CompleteResponse methods never return OAuth tokens.
func (client *Client) CompleteTokens(ctx context.Context, response AuthorizationResponse, attempt ProtectedAttempt) (Completion, error) {
	return client.complete(ctx, response, attempt, true)
}

func (client *Client) complete(ctx context.Context, response AuthorizationResponse, attempt ProtectedAttempt, returnTokens bool) (Completion, error) {
	if client == nil {
		return Completion{}, fmt.Errorf("OIDC client is not initialized")
	}
	state := response.State
	if response.ResponseJWT != "" {
		outerMode := response.Mode
		verified, err := client.provider.verifyAuthorizationResponseJWT(ctx, response.ResponseJWT, client.clock().UTC())
		if err != nil {
			return Completion{}, err
		}
		verified.ResponseJWT = response.ResponseJWT
		response = verified
		response.Mode = outerMode
		state = response.State
	}
	material, err := recoverLoginMaterial(state, attempt.StateHash[:], attempt.NonceCiphertext[:], attempt.PKCEVerifierCiphertext[:])
	if err != nil {
		return Completion{}, err
	}
	contextEnvelope, decodeErr := base64.RawURLEncoding.Strict().DecodeString(attempt.ContextCiphertext)
	if decodeErr != nil {
		return Completion{}, fmt.Errorf("OIDC attempt context encoding is invalid")
	}
	attemptContext, err := openAttemptContext(state, attempt.StateHash, contextEnvelope)
	if err != nil {
		return Completion{}, err
	}
	if err := attemptContext.validateFor(client); err != nil {
		return Completion{}, err
	}
	if err := validateResponseMode(attemptContext.ResponseMode, response); err != nil {
		return Completion{}, err
	}
	if attemptContext.RequireResponseIssuer {
		if response.Issuer == "" || response.Issuer != attemptContext.Issuer {
			return Completion{}, fmt.Errorf("OIDC authorization response issuer is invalid")
		}
	} else if response.Issuer != "" && response.Issuer != attemptContext.Issuer {
		return Completion{}, fmt.Errorf("OIDC authorization response issuer is invalid")
	}
	if response.Error != nil {
		return Completion{}, response.Error
	}
	claims, tokens, err := client.provider.exchangeInitialLoginWithContext(ctx, response.Code, material, attemptContext, client.clock().UTC())
	if err != nil {
		return Completion{}, err
	}
	completion := Completion{Identity: Identity{
		Issuer:      claims.issuer,
		Subject:     claims.subject,
		DisplayName: claims.displayName,
		Email:       cloneString(claims.email),
		PictureURL:  cloneString(claims.avatarURL),
	}}
	if returnTokens {
		expiresAt := time.Time{}
		if tokens.ExpiresIn > 0 {
			expiresAt = client.clock().UTC().Add(time.Duration(tokens.ExpiresIn) * time.Second)
		}
		completion.Tokens = TokenSet{AccessToken: tokens.AccessToken, TokenType: tokens.TokenType, RefreshToken: tokens.RefreshToken, IDToken: tokens.IDToken, Scope: strings.Fields(tokens.Scope), ExpiresAt: expiresAt}
	}
	return completion, nil
}

// RefreshRequest binds refresh to the previously verified subject. The caller
// must atomically replace its stored token set only after success.
type RefreshRequest struct {
	RefreshToken    string
	ExpectedSubject string
	Scopes          []string
}

// Refresh exchanges an explicitly retained refresh token. It never performs
// storage and returns a complete replacement token set for atomic rotation.
func (client *Client) Refresh(ctx context.Context, request RefreshRequest) (TokenSet, error) {
	if client == nil || client.clock == nil {
		return TokenSet{}, fmt.Errorf("OIDC client is not initialized")
	}
	if request.ExpectedSubject == "" || len(request.ExpectedSubject) > 512 {
		return TokenSet{}, fmt.Errorf("OIDC refresh subject is invalid")
	}
	validated, err := validateAuthorizationOptions(AuthorizationOptions{Scopes: request.Scopes}, IdentityPolicy{})
	if err != nil {
		return TokenSet{}, err
	}
	now := client.clock().UTC()
	tokens, err := client.provider.refreshToken(ctx, request.RefreshToken, validated.scopes, now)
	if err != nil {
		return TokenSet{}, err
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = request.RefreshToken
	}
	if tokens.IDToken != "" {
		idToken, claims, err := client.provider.verifyIDToken(ctx, tokens.IDToken)
		if err != nil || idToken.Subject != request.ExpectedSubject {
			return TokenSet{}, fmt.Errorf("OIDC refreshed ID token is invalid")
		}
		if err := client.provider.validateIDTokenBinding(idToken, claims, attemptContext{}, now); err != nil {
			return TokenSet{}, err
		}
	}
	return TokenSet{AccessToken: tokens.AccessToken, TokenType: tokens.TokenType, RefreshToken: tokens.RefreshToken, IDToken: tokens.IDToken, Scope: strings.Fields(tokens.Scope), ExpiresAt: client.clock().UTC().Add(time.Duration(tokens.ExpiresIn) * time.Second)}, nil
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
