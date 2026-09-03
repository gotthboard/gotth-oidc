package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func (provider discoveredOIDCProvider) initialAuthorizationURL(material loginMaterial) (string, error) {
	options, err := validateAuthorizationOptions(AuthorizationOptions{}, IdentityPolicy{RequireDisplayName: true})
	if err != nil {
		return "", err
	}
	return provider.initialAuthorizationURLWithOptions(context.Background(), material, options, time.Now().UTC())
}

func (provider discoveredOIDCProvider) initialAuthorizationURLWithOptions(ctx context.Context, material loginMaterial, options validatedAuthorizationOptions, now time.Time) (string, error) {
	if provider.verifier == nil || provider.httpClient == nil || provider.oauth2Config.ClientID == "" || provider.oauth2Config.Endpoint.AuthURL == "" || provider.oauth2Config.RedirectURL == "" {
		return "", fmt.Errorf("OIDC provider is not initialized for initial authorization")
	}
	decode := func(value string) ([loginSecretBytes]byte, error) {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		defer clear(decoded)
		if err != nil || len(decoded) != loginSecretBytes {
			return [loginSecretBytes]byte{}, fmt.Errorf("login authorization material has an invalid encoding or length")
		}
		var result [loginSecretBytes]byte
		copy(result[:], decoded)
		return result, nil
	}
	state, err := decode(material.state)
	if err != nil {
		return "", err
	}
	defer clear(state[:])
	nonce, err := decode(material.nonce)
	if err != nil {
		return "", err
	}
	defer clear(nonce[:])
	verifier, err := decode(material.pkceVerifier)
	if err != nil {
		return "", err
	}
	defer clear(verifier[:])
	if bytes.Equal(state[:], nonce[:]) || bytes.Equal(state[:], verifier[:]) || bytes.Equal(nonce[:], verifier[:]) {
		return "", fmt.Errorf("login authorization material repeats a value")
	}
	parameters := url.Values{
		"response_type":         {"code"},
		"client_id":             {provider.oauth2Config.ClientID},
		"redirect_uri":          {provider.oauth2Config.RedirectURL},
		"scope":                 {strings.Join(options.scopes, " ")},
		"state":                 {material.state},
		"nonce":                 {material.nonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(material.pkceVerifier)},
		"code_challenge_method": {"S256"},
	}
	if provider.dpopSigner != nil {
		thumbprinter, ok := provider.dpopSigner.(DPoPKeyThumbprinter)
		if !ok {
			return "", fmt.Errorf("OIDC DPoP signer does not expose a public-key thumbprint")
		}
		thumbprint, err := thumbprinter.DPoPKeyThumbprint(ctx)
		if err != nil || thumbprint == "" || len(thumbprint) > 128 || strings.ContainsAny(thumbprint, "\r\n\t ") {
			return "", fmt.Errorf("OIDC DPoP key thumbprint is invalid")
		}
		parameters.Set("dpop_jkt", thumbprint)
	}
	setJoined := func(name string, values []string) {
		if len(values) != 0 {
			parameters.Set(name, strings.Join(values, " "))
		}
	}
	setJoined("prompt", options.prompt)
	setJoined("acr_values", options.acrValues)
	setJoined("ui_locales", options.uiLocales)
	setJoined("claims_locales", options.claimsLocales)
	if options.maxAgeSeconds != nil {
		parameters.Set("max_age", strconv.FormatInt(*options.maxAgeSeconds, 10))
	}
	if options.loginHint != "" {
		parameters.Set("login_hint", options.loginHint)
	}
	if options.idTokenHint != "" {
		parameters.Set("id_token_hint", options.idTokenHint)
	}
	if len(options.claims) != 0 {
		if !provider.metadata.ClaimsParameterSupported {
			return "", fmt.Errorf("OIDC provider does not advertise the claims parameter")
		}
		parameters.Set("claims", string(options.claims))
	}
	if len(provider.metadata.ACRValues) != 0 {
		for _, requested := range options.acrValues {
			if !slices.Contains(provider.metadata.ACRValues, requested) {
				return "", fmt.Errorf("OIDC provider does not advertise requested ACR value")
			}
		}
	}
	if options.responseMode != ResponseModeQuery {
		if !endpointSupports(provider.metadata.ResponseModes, string(options.responseMode), "query", "fragment") {
			return "", fmt.Errorf("OIDC provider does not advertise response mode %s", options.responseMode)
		}
		parameters.Set("response_mode", string(options.responseMode))
	}
	if options.offlineAccess && !slices.Contains(options.prompt, "consent") {
		return "", fmt.Errorf("OIDC offline access requires prompt=consent")
	}
	if options.useRequestObject {
		if provider.requestObjectSigner == nil {
			return "", fmt.Errorf("OIDC request object signer is not configured")
		}
		requestClaims := make(map[string]any, len(parameters)+4)
		for name, values := range parameters {
			requestClaims[name] = values[0]
		}
		requestClaims["iss"] = provider.oauth2Config.ClientID
		requestClaims["aud"] = provider.issuer
		requestClaims["iat"] = now.Unix()
		requestClaims["exp"] = now.Add(5 * time.Minute).Unix()
		requestID := sha256.Sum256([]byte(material.state))
		requestClaims["jti"] = base64.RawURLEncoding.EncodeToString(requestID[:])
		raw, err := json.Marshal(requestClaims)
		if err != nil {
			return "", fmt.Errorf("encode OIDC request object claims: %w", err)
		}
		requestObject, err := provider.requestObjectSigner.SignJWT(ctx, "oauth-authz-req+jwt", raw)
		if err != nil || requestObject == "" {
			return "", fmt.Errorf("sign OIDC request object failed")
		}
		parameters = url.Values{"client_id": {provider.oauth2Config.ClientID}, "request": {requestObject}}
	}
	if options.usePAR || provider.metadata.RequirePAR || provider.enablePAR {
		requestURI, err := provider.pushAuthorizationRequest(ctx, parameters, now)
		if err != nil {
			return "", err
		}
		parameters = url.Values{"client_id": {provider.oauth2Config.ClientID}, "request_uri": {requestURI}}
	}
	authorizationEndpoint, err := url.Parse(provider.oauth2Config.Endpoint.AuthURL)
	if err != nil {
		return "", fmt.Errorf("OIDC authorization endpoint is invalid")
	}
	query := authorizationEndpoint.Query()
	for name, values := range parameters {
		query[name] = append([]string(nil), values...)
	}
	authorizationEndpoint.RawQuery = query.Encode()
	return authorizationEndpoint.String(), nil
}
