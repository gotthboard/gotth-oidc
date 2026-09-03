package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// EndpointKind identifies one discovered network endpoint. Policies must make
// an independent decision for every endpoint; discovery is not an SSRF waiver.
type EndpointKind string

const (
	EndpointAuthorization EndpointKind = "authorization"
	EndpointToken         EndpointKind = "token"
	EndpointJWKS          EndpointKind = "jwks"
	EndpointUserInfo      EndpointKind = "userinfo"
	EndpointPAR           EndpointKind = "pushed_authorization_request"
	EndpointRegistration  EndpointKind = "registration"
	EndpointLogout        EndpointKind = "end_session"
	EndpointSession       EndpointKind = "check_session"
	EndpointRevocation    EndpointKind = "revocation"
)

// EndpointPolicy decides whether a discovered endpoint may be contacted.
// Implementations must be deterministic and must not perform network I/O.
type EndpointPolicy interface {
	AllowEndpoint(kind EndpointKind, issuer, endpoint *url.URL) error
}

// EndpointPolicyFunc adapts a function to EndpointPolicy.
type EndpointPolicyFunc func(kind EndpointKind, issuer, endpoint *url.URL) error

func (policy EndpointPolicyFunc) AllowEndpoint(kind EndpointKind, issuer, endpoint *url.URL) error {
	if policy == nil {
		return fmt.Errorf("OIDC endpoint policy is nil")
	}
	return policy(kind, issuer, endpoint)
}

// SameOriginEndpoints is the conservative default. Standards-compatible
// deployments using separate endpoint hosts must choose HTTPSAnyOriginEndpoints
// or provide a narrower allowlist policy.
var SameOriginEndpoints EndpointPolicy = EndpointPolicyFunc(func(_ EndpointKind, issuer, endpoint *url.URL) error {
	if issuer == nil || endpoint == nil || !strings.EqualFold(issuer.Scheme, endpoint.Scheme) || !strings.EqualFold(issuer.Host, endpoint.Host) {
		return fmt.Errorf("OIDC endpoint escapes the configured issuer origin")
	}
	return nil
})

// HTTPSAnyOriginEndpoints admits any syntactically valid HTTPS endpoint. It is
// standards-compatible but too broad for consumers that do not trust provider
// metadata to select outbound destinations.
var HTTPSAnyOriginEndpoints EndpointPolicy = EndpointPolicyFunc(func(_ EndpointKind, _ *url.URL, endpoint *url.URL) error {
	if endpoint == nil || !strings.EqualFold(endpoint.Scheme, "https") {
		return fmt.Errorf("OIDC endpoint must use HTTPS")
	}
	return nil
})

// ClientAuthenticationMethod is the token-endpoint authentication method.
type ClientAuthenticationMethod string

const (
	ClientAuthNone          ClientAuthenticationMethod = "none"
	ClientSecretBasic       ClientAuthenticationMethod = "client_secret_basic"
	ClientSecretPost        ClientAuthenticationMethod = "client_secret_post"
	ClientSecretJWT         ClientAuthenticationMethod = "client_secret_jwt"
	PrivateKeyJWT           ClientAuthenticationMethod = "private_key_jwt"
	TLSClientAuth           ClientAuthenticationMethod = "tls_client_auth"
	SelfSignedTLSClientAuth ClientAuthenticationMethod = "self_signed_tls_client_auth"
)

// JWTSigner signs one bounded JSON claims object for request objects, client
// assertions, DPoP proofs, or other purpose-specific JWTs. The caller owns the
// signing key and its rotation.
type JWTSigner interface {
	Algorithm() string
	SignJWT(ctx context.Context, typ string, claims json.RawMessage) (string, error)
}

// DPoPKeyThumbprinter exposes the RFC 7638 thumbprint of the public key used
// for DPoP. DPoP signers must implement it so authorization codes can be bound
// with dpop_jkt before the token request.
type DPoPKeyThumbprinter interface {
	DPoPKeyThumbprint(ctx context.Context) (string, error)
}

// JWTDecrypter unwraps one compact JWE and returns the nested compact signed
// JWT. Implementations must enforce their own key-management algorithm and
// content-encryption allowlists.
type JWTDecrypter interface {
	DecryptJWT(ctx context.Context, compactJWE string) (string, error)
}

// ClientAuthentication configures explicit token/PAR endpoint authentication.
// Signer is required for JWT methods. TLS methods require an mTLS-capable
// Transport and discovered mutual-TLS endpoint aliases.
type ClientAuthentication struct {
	Method ClientAuthenticationMethod
	Signer JWTSigner
}

// IdentityPolicy determines which optional profile facts are fetched and
// required. Issuer and subject are always required.
type IdentityPolicy struct {
	UseUserInfo          bool
	RequireDisplayName   bool
	RequireVerifiedEmail bool
}

// ResponseMode identifies supported authorization-response encodings.
type ResponseMode string

const (
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFormPost ResponseMode = "form_post"
	ResponseModeJWT      ResponseMode = "jwt"
	ResponseModeQueryJWT ResponseMode = "query.jwt"
	ResponseModeFormJWT  ResponseMode = "form_post.jwt"
)

// AuthorizationOptions are bounded optional OpenID Connect request parameters.
// Zero values select the interoperable Authorization Code default.
type AuthorizationOptions struct {
	Scopes           []string
	Prompt           []string
	MaxAge           *time.Duration
	ACRValues        []string
	LoginHint        string
	IDTokenHint      string
	UILocales        []string
	ClaimsLocales    []string
	Claims           json.RawMessage
	ResponseMode     ResponseMode
	UseUserInfo      bool
	RequireName      bool
	RequireEmail     bool
	OfflineAccess    bool
	UsePAR           bool
	UseRequestObject bool
}

type validatedAuthorizationOptions struct {
	scopes           []string
	prompt           []string
	maxAgeSeconds    *int64
	acrValues        []string
	loginHint        string
	idTokenHint      string
	uiLocales        []string
	claimsLocales    []string
	claims           json.RawMessage
	responseMode     ResponseMode
	useUserInfo      bool
	requireName      bool
	requireEmail     bool
	offlineAccess    bool
	usePAR           bool
	useRequestObject bool
}

func validateAuthorizationOptions(options AuthorizationOptions, defaults IdentityPolicy) (validatedAuthorizationOptions, error) {
	validateToken := func(name, value string, maximum int) error {
		if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("OIDC %s value is invalid", name)
		}
		return nil
	}
	copyTokens := func(name string, values []string, maximumCount, maximumLength int) ([]string, error) {
		if len(values) > maximumCount {
			return nil, fmt.Errorf("OIDC %s has too many values", name)
		}
		result := make([]string, 0, len(values))
		for _, value := range values {
			if err := validateToken(name, value, maximumLength); err != nil || slices.Contains(result, value) {
				return nil, fmt.Errorf("OIDC %s contains an invalid or duplicate value", name)
			}
			result = append(result, value)
		}
		return result, nil
	}
	scopes, err := copyTokens("scope", options.Scopes, 32, 128)
	if err != nil {
		return validatedAuthorizationOptions{}, err
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	if options.OfflineAccess && !slices.Contains(scopes, "offline_access") {
		scopes = append(scopes, "offline_access")
	}
	prompt, err := copyTokens("prompt", options.Prompt, 8, 64)
	if err != nil {
		return validatedAuthorizationOptions{}, err
	}
	if slices.Contains(prompt, "none") && len(prompt) != 1 {
		return validatedAuthorizationOptions{}, fmt.Errorf("OIDC prompt none cannot be combined with another prompt")
	}
	acrValues, err := copyTokens("ACR", options.ACRValues, 16, 256)
	if err != nil {
		return validatedAuthorizationOptions{}, err
	}
	uiLocales, err := copyTokens("ui_locales", options.UILocales, 16, 64)
	if err != nil {
		return validatedAuthorizationOptions{}, err
	}
	claimsLocales, err := copyTokens("claims_locales", options.ClaimsLocales, 16, 64)
	if err != nil {
		return validatedAuthorizationOptions{}, err
	}
	for name, value := range map[string]string{"login_hint": options.LoginHint, "id_token_hint": options.IDTokenHint} {
		if value != "" && (len(value) > 4096 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0) {
			return validatedAuthorizationOptions{}, fmt.Errorf("OIDC %s is invalid", name)
		}
	}
	var maxAge *int64
	if options.MaxAge != nil {
		if *options.MaxAge < 0 || *options.MaxAge > 365*24*time.Hour || *options.MaxAge%time.Second != 0 {
			return validatedAuthorizationOptions{}, fmt.Errorf("OIDC max_age is invalid")
		}
		seconds := int64(*options.MaxAge / time.Second)
		maxAge = &seconds
	}
	claims := json.RawMessage(nil)
	if len(options.Claims) != 0 {
		if len(options.Claims) > 16<<10 || !json.Valid(options.Claims) {
			return validatedAuthorizationOptions{}, fmt.Errorf("OIDC claims request is invalid")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(options.Claims, &object); err != nil || object == nil {
			return validatedAuthorizationOptions{}, fmt.Errorf("OIDC claims request must be a JSON object")
		}
		claims = append(json.RawMessage(nil), options.Claims...)
	}
	mode := options.ResponseMode
	if mode == "" {
		mode = ResponseModeQuery
	}
	switch mode {
	case ResponseModeQuery, ResponseModeFormPost, ResponseModeJWT, ResponseModeQueryJWT, ResponseModeFormJWT:
	default:
		return validatedAuthorizationOptions{}, fmt.Errorf("OIDC response mode is unsupported")
	}
	return validatedAuthorizationOptions{
		scopes: scopes, prompt: prompt, maxAgeSeconds: maxAge, acrValues: acrValues,
		loginHint: options.LoginHint, idTokenHint: options.IDTokenHint,
		uiLocales: uiLocales, claimsLocales: claimsLocales, claims: claims,
		responseMode: mode, useUserInfo: options.UseUserInfo || defaults.UseUserInfo,
		requireName:   options.RequireName || defaults.RequireDisplayName,
		requireEmail:  options.RequireEmail || defaults.RequireVerifiedEmail,
		offlineAccess: options.OfflineAccess, usePAR: options.UsePAR,
		useRequestObject: options.UseRequestObject,
	}, nil
}
