package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const maxDirectResponseBytes = 512 << 10

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type endpointError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (err endpointError) Error() string {
	if err.Code == "" {
		return "OIDC endpoint request failed"
	}
	return "OIDC endpoint request failed: " + err.Code
}

func (provider discoveredOIDCProvider) pushAuthorizationRequest(ctx context.Context, parameters url.Values, now time.Time) (string, error) {
	endpoint := provider.metadata.PAREndpoint
	if provider.enableMutualTLS && provider.metadata.MTLSEndpointAliases.PAREndpoint != "" {
		endpoint = provider.metadata.MTLSEndpointAliases.PAREndpoint
	}
	if endpoint == "" {
		return "", fmt.Errorf("OIDC provider does not advertise PAR")
	}
	form := cloneValues(parameters)
	var response struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	if err := provider.doAuthenticatedJSON(ctx, endpoint, form, now, &response); err != nil {
		return "", fmt.Errorf("OIDC PAR failed: %w", err)
	}
	requestURI, parseErr := url.Parse(response.RequestURI)
	if parseErr != nil || response.RequestURI == "" || len(response.RequestURI) > 4096 || requestURI.Scheme == "" || requestURI.Fragment != "" || strings.ContainsAny(response.RequestURI, "\r\n\t ") || response.ExpiresIn <= 0 {
		return "", fmt.Errorf("OIDC PAR response is invalid")
	}
	return response.RequestURI, nil
}

func (provider discoveredOIDCProvider) exchangeCode(ctx context.Context, code, verifier string, now time.Time) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {provider.oauth2Config.RedirectURL},
		"code_verifier": {verifier},
	}
	return provider.performTokenRequest(ctx, form, now)
}

func (provider discoveredOIDCProvider) refreshToken(ctx context.Context, refreshToken string, scopes []string, now time.Time) (tokenResponse, error) {
	if refreshToken == "" || len(refreshToken) > 64<<10 {
		return tokenResponse{}, fmt.Errorf("OIDC refresh token is invalid")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if len(scopes) != 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return provider.performTokenRequest(ctx, form, now)
}

func (provider discoveredOIDCProvider) performTokenRequest(ctx context.Context, form url.Values, now time.Time) (tokenResponse, error) {
	var response tokenResponse
	if err := provider.doAuthenticatedJSON(ctx, provider.oauth2Config.Endpoint.TokenURL, form, now, &response); err != nil {
		return tokenResponse{}, fmt.Errorf("OIDC token request failed: %w", err)
	}
	if response.AccessToken == "" || len(response.AccessToken) > 64<<10 || response.TokenType == "" {
		return tokenResponse{}, fmt.Errorf("OIDC token response is invalid")
	}
	expectedType := "Bearer"
	if provider.dpopSigner != nil {
		expectedType = "DPoP"
	}
	if !strings.EqualFold(response.TokenType, expectedType) {
		return tokenResponse{}, fmt.Errorf("OIDC token response has unsupported token type")
	}
	if len(response.RefreshToken) > 64<<10 || len(response.IDToken) > maxOIDCIDTokenBytes || response.ExpiresIn < 0 {
		return tokenResponse{}, fmt.Errorf("OIDC token response exceeds bounds")
	}
	return response, nil
}

func (provider discoveredOIDCProvider) doAuthenticatedJSON(ctx context.Context, endpoint string, form url.Values, now time.Time, target any) error {
	nonce := ""
	for attempt := 0; attempt < 2; attempt++ {
		request, err := provider.newAuthenticatedFormRequest(ctx, endpoint, form, now, nonce)
		if err != nil {
			return err
		}
		response, err := provider.httpClient.Do(request)
		if err != nil {
			return err
		}
		mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxDirectResponseBytes+1))
		_ = response.Body.Close()
		if readErr != nil || len(body) > maxDirectResponseBytes {
			return fmt.Errorf("OIDC endpoint response is unreadable or oversized")
		}
		if mediaType != "application/json" {
			return fmt.Errorf("OIDC endpoint returned an invalid content type")
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			var failure endpointError
			_ = json.Unmarshal(body, &failure)
			candidateNonce := response.Header.Get("DPoP-Nonce")
			if attempt == 0 && provider.dpopSigner != nil && failure.Code == "use_dpop_nonce" && validDPoPNonce(candidateNonce) {
				nonce = candidateNonce
				continue
			}
			if failure.Code != "" {
				return failure
			}
			return fmt.Errorf("OIDC endpoint returned HTTP %d", response.StatusCode)
		}
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("OIDC endpoint returned invalid JSON")
		}
		return nil
	}
	return fmt.Errorf("OIDC DPoP nonce retry failed")
}

func validDPoPNonce(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\t ")
}

func (provider discoveredOIDCProvider) newAuthenticatedFormRequest(ctx context.Context, endpoint string, form url.Values, now time.Time, dpopNonce string) (*http.Request, error) {
	if ctx == nil {
		return nil, fmt.Errorf("OIDC endpoint context is required")
	}
	form = cloneValues(form)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("construct OIDC endpoint request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	switch provider.clientAuth.Method {
	case ClientAuthNone, TLSClientAuth, SelfSignedTLSClientAuth:
		form.Set("client_id", provider.oauth2Config.ClientID)
	case ClientSecretBasic:
		request.SetBasicAuth(url.QueryEscape(provider.oauth2Config.ClientID), url.QueryEscape(provider.clientSecret))
	case ClientSecretPost:
		form.Set("client_id", provider.oauth2Config.ClientID)
		form.Set("client_secret", provider.clientSecret)
	case ClientSecretJWT, PrivateKeyJWT:
		assertion, assertionErr := provider.clientAssertion(ctx, endpoint, now)
		if assertionErr != nil {
			return nil, assertionErr
		}
		form.Set("client_id", provider.oauth2Config.ClientID)
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	default:
		return nil, fmt.Errorf("OIDC client authentication is unsupported")
	}
	request.Body = io.NopCloser(strings.NewReader(form.Encode()))
	request.ContentLength = int64(len(form.Encode()))
	if provider.dpopSigner != nil {
		proof, proofErr := provider.dpopProof(ctx, http.MethodPost, endpoint, "", dpopNonce, now)
		if proofErr != nil {
			return nil, proofErr
		}
		request.Header.Set("DPoP", proof)
	}
	return request, nil
}

func (provider discoveredOIDCProvider) clientAssertion(ctx context.Context, audience string, now time.Time) (string, error) {
	if provider.clientAuth.Signer == nil {
		return "", fmt.Errorf("OIDC client assertion signer is missing")
	}
	jti, err := randomIdentifier()
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": provider.oauth2Config.ClientID, "sub": provider.oauth2Config.ClientID,
		"aud": audience, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": jti,
	})
	if err != nil {
		return "", fmt.Errorf("encode OIDC client assertion: %w", err)
	}
	assertion, err := provider.clientAuth.Signer.SignJWT(ctx, "JWT", claims)
	if err != nil || assertion == "" {
		return "", fmt.Errorf("sign OIDC client assertion failed")
	}
	return assertion, nil
}

func (provider discoveredOIDCProvider) dpopProof(ctx context.Context, method, endpoint, accessToken, nonce string, now time.Time) (string, error) {
	if provider.dpopSigner == nil {
		return "", fmt.Errorf("OIDC DPoP signer is missing")
	}
	jti, err := randomIdentifier()
	if err != nil {
		return "", err
	}
	htu, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("OIDC DPoP target URI is invalid")
	}
	htu.RawQuery = ""
	htu.Fragment = ""
	claims := map[string]any{"jti": jti, "htm": strings.ToUpper(method), "htu": htu.String(), "iat": now.Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		hash := sha256String(accessToken)
		claims["ath"] = hash
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode OIDC DPoP proof: %w", err)
	}
	proof, err := provider.dpopSigner.SignJWT(ctx, "dpop+jwt", raw)
	if err != nil || proof == "" {
		return "", fmt.Errorf("sign OIDC DPoP proof failed")
	}
	header, err := parseCompactJWTHeader(proof)
	var proofKey jose.JSONWebKey
	if err != nil || header.Type != "dpop+jwt" || len(header.JWK) == 0 || json.Unmarshal(header.JWK, &proofKey) != nil || !proofKey.Valid() || proofKey.IsPublic() == false || !containsString(safeProofAlgorithms(), header.Algorithm) {
		return "", fmt.Errorf("OIDC DPoP proof header is invalid")
	}
	return proof, nil
}

func randomIdentifier() (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("read OIDC identifier entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func cloneValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for name, entries := range values {
		clone[name] = append([]string(nil), entries...)
	}
	return clone
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
