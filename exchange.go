package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

const (
	maxOIDCAuthorizationCodeBytes = 4096
	maxOIDCIDTokenBytes           = 64 << 10
)

func (provider discoveredOIDCProvider) exchangeInitialLogin(ctx context.Context, code string, material loginMaterial) (verifiedIdentityClaims, error) {
	claims, _, err := provider.exchangeInitialLoginWithContext(ctx, code, material, attemptContext{RequireName: true}, time.Now().UTC())
	return claims, err
}

func (provider discoveredOIDCProvider) exchangeInitialLoginWithContext(ctx context.Context, code string, material loginMaterial, attempt attemptContext, now time.Time) (verifiedIdentityClaims, tokenResponse, error) {
	if ctx == nil {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("OIDC exchange context is required")
	}
	if err := ctx.Err(); err != nil {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("exchange OIDC code: %w", err)
	}
	if provider.verifier == nil || provider.httpClient == nil || provider.oauth2Config.ClientID == "" || provider.oauth2Config.Endpoint.TokenURL == "" || provider.oauth2Config.RedirectURL == "" {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("OIDC provider is not initialized for code exchange")
	}
	if len(code) == 0 || len(code) > maxOIDCAuthorizationCodeBytes || !utf8.ValidString(code) || strings.IndexFunc(code, func(character rune) bool { return unicode.IsControl(character) || unicode.IsSpace(character) }) >= 0 {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("OIDC authorization code is invalid")
	}
	decodeSecret := func(value string) ([loginSecretBytes]byte, error) {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		defer clear(decoded)
		if err != nil || len(decoded) != loginSecretBytes {
			return [loginSecretBytes]byte{}, fmt.Errorf("OIDC login material has an invalid encoding or length")
		}
		var result [loginSecretBytes]byte
		copy(result[:], decoded)
		return result, nil
	}
	expectedNonce, err := decodeSecret(material.nonce)
	if err != nil {
		return verifiedIdentityClaims{}, tokenResponse{}, err
	}
	defer clear(expectedNonce[:])
	verifier, err := decodeSecret(material.pkceVerifier)
	if err != nil {
		return verifiedIdentityClaims{}, tokenResponse{}, err
	}
	defer clear(verifier[:])
	tokens, err := provider.exchangeCode(ctx, code, material.pkceVerifier, now)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("exchange OIDC code: %w", contextError)
		}
		return verifiedIdentityClaims{}, tokenResponse{}, err
	}
	if tokens.IDToken == "" {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("OIDC code exchange returned no ID token")
	}
	idToken, claims, err := provider.verifyIDToken(ctx, tokens.IDToken)
	if err != nil {
		return verifiedIdentityClaims{}, tokenResponse{}, err
	}
	actualNonce, err := decodeSecret(idToken.Nonce)
	if err != nil || subtle.ConstantTimeCompare(expectedNonce[:], actualNonce[:]) != 1 {
		clear(actualNonce[:])
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("OIDC ID token nonce is invalid")
	}
	clear(actualNonce[:])
	if idToken.AccessTokenHash != "" && (tokens.AccessToken == "" || idToken.VerifyAccessToken(tokens.AccessToken) != nil) {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("OIDC access-token hash verification failed")
	}
	if err := provider.validateIDTokenBinding(idToken, claims, attempt, now); err != nil {
		return verifiedIdentityClaims{}, tokenResponse{}, err
	}
	if attempt.UseUserInfo {
		userInfoClaims, err := provider.fetchUserInfo(ctx, tokens, idToken.Subject, now)
		if err != nil {
			return verifiedIdentityClaims{}, tokenResponse{}, err
		}
		for _, name := range []string{"name", "email", "email_verified", "picture"} {
			if value, present := userInfoClaims[name]; present {
				claims[name] = value
			}
		}
	}
	accepted, err := validateIdentityClaimsWithPolicy(idToken.Issuer, idToken.Subject, claims, attempt.RequireName, attempt.RequireEmail)
	if err != nil {
		return verifiedIdentityClaims{}, tokenResponse{}, fmt.Errorf("validate verified OIDC claims: %w", err)
	}
	return accepted, tokens, nil
}

func (provider discoveredOIDCProvider) verifyIDToken(ctx context.Context, raw string) (*coreoidc.IDToken, map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxOIDCIDTokenBytes {
		return nil, nil, fmt.Errorf("OIDC code exchange returned an invalid ID token")
	}
	if strings.Count(raw, ".") == 4 {
		if provider.tokenDecrypter == nil {
			return nil, nil, fmt.Errorf("OIDC ID token is encrypted but no decrypter is configured")
		}
		decrypted, err := provider.tokenDecrypter.DecryptJWT(ctx, raw)
		if err != nil || decrypted == "" || len(decrypted) > maxOIDCIDTokenBytes {
			return nil, nil, fmt.Errorf("decrypt OIDC ID token failed")
		}
		raw = decrypted
	}
	verificationContext := coreoidc.ClientContext(ctx, provider.httpClient)
	idToken, err := provider.verifier.Verify(verificationContext, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("OIDC ID token verification failed")
	}
	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil || claims == nil {
		return nil, nil, fmt.Errorf("decode verified OIDC claims failed")
	}
	return idToken, claims, nil
}

func (provider discoveredOIDCProvider) validateIDTokenBinding(idToken *coreoidc.IDToken, claims map[string]json.RawMessage, attempt attemptContext, now time.Time) error {
	if idToken == nil || len(idToken.Audience) == 0 || !slices.Contains(idToken.Audience, provider.oauth2Config.ClientID) {
		return fmt.Errorf("OIDC ID token audience is invalid")
	}
	var additional []string
	for _, audience := range idToken.Audience {
		if audience != provider.oauth2Config.ClientID {
			additional = append(additional, audience)
			if !slices.Contains(provider.trustedAudiences, audience) {
				return fmt.Errorf("OIDC ID token contains an untrusted audience")
			}
		}
	}
	azp, err := claimString(claims, "azp", false)
	if err != nil {
		return err
	}
	if len(additional) != 0 && azp == "" {
		return fmt.Errorf("OIDC multi-audience ID token omits azp")
	}
	if azp != "" && azp != provider.oauth2Config.ClientID {
		return fmt.Errorf("OIDC ID token authorized party is invalid")
	}
	if attempt.MaxAgeSeconds != nil {
		authTime, err := claimUnixTime(claims, "auth_time")
		if err != nil {
			return fmt.Errorf("OIDC ID token auth_time is invalid")
		}
		if authTime.After(now.Add(time.Minute)) || now.After(authTime.Add(time.Duration(*attempt.MaxAgeSeconds)*time.Second+time.Minute)) {
			return fmt.Errorf("OIDC authentication is older than max_age")
		}
	}
	if len(attempt.ACRValues) != 0 {
		acr, err := claimString(claims, "acr", true)
		if err != nil || !slices.Contains(attempt.ACRValues, acr) {
			return fmt.Errorf("OIDC ID token ACR is unacceptable")
		}
	}
	return nil
}

func (provider discoveredOIDCProvider) fetchUserInfo(ctx context.Context, tokens tokenResponse, expectedSubject string, now time.Time) (map[string]json.RawMessage, error) {
	endpoint := provider.metadata.UserInfoEndpoint
	if provider.enableMutualTLS && provider.metadata.MTLSEndpointAliases.UserInfoEndpoint != "" {
		endpoint = provider.metadata.MTLSEndpointAliases.UserInfoEndpoint
	}
	if endpoint == "" {
		return nil, fmt.Errorf("OIDC provider does not advertise UserInfo")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("construct OIDC UserInfo request: %w", err)
	}
	request.Header.Set("Accept", "application/json, application/jwt")
	request.Header.Set("Authorization", tokens.TokenType+" "+tokens.AccessToken)
	if provider.dpopSigner != nil {
		proof, err := provider.dpopProof(ctx, http.MethodGet, endpoint, tokens.AccessToken, "", now)
		if err != nil {
			return nil, err
		}
		request.Header.Set("DPoP", proof)
	}
	response, err := provider.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("OIDC UserInfo request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC UserInfo request failed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDirectResponseBytes+1))
	if err != nil || len(body) > maxDirectResponseBytes {
		return nil, fmt.Errorf("OIDC UserInfo response is unreadable or oversized")
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	var claims map[string]json.RawMessage
	signed := false
	if mediaType == "application/jwt" {
		signed = true
		raw := string(body)
		if strings.Count(raw, ".") == 4 {
			if provider.tokenDecrypter == nil {
				return nil, fmt.Errorf("OIDC UserInfo JWT is encrypted but no decrypter is configured")
			}
			raw, err = provider.tokenDecrypter.DecryptJWT(ctx, raw)
			if err != nil {
				return nil, fmt.Errorf("decrypt OIDC UserInfo JWT failed")
			}
		}
		header, headerErr := parseCompactJWTHeader(raw)
		if headerErr != nil || (len(provider.metadata.UserInfoSigningAlgorithms) != 0 && !slices.Contains(provider.metadata.UserInfoSigningAlgorithms, header.Algorithm)) || !containsString(safeSigningAlgorithms([]string{header.Algorithm}), header.Algorithm) {
			return nil, fmt.Errorf("OIDC UserInfo JWT header is invalid")
		}
		payload, err := provider.keySet.VerifySignature(coreoidc.ClientContext(ctx, provider.httpClient), raw)
		if err != nil || json.Unmarshal(payload, &claims) != nil {
			return nil, fmt.Errorf("OIDC UserInfo JWT verification failed")
		}
	} else if mediaType == "application/json" {
		if err := json.Unmarshal(body, &claims); err != nil {
			return nil, fmt.Errorf("OIDC UserInfo response is invalid")
		}
	} else {
		return nil, fmt.Errorf("OIDC UserInfo response has an invalid content type")
	}
	if signed {
		issuer, err := claimString(claims, "iss", true)
		if err != nil || issuer != provider.issuer {
			return nil, fmt.Errorf("OIDC UserInfo JWT issuer is invalid")
		}
		rawAudience, present := claims["aud"]
		var audience audienceClaim
		if !present || json.Unmarshal(rawAudience, &audience) != nil || !containsString([]string(audience), provider.oauth2Config.ClientID) {
			return nil, fmt.Errorf("OIDC UserInfo JWT audience is invalid")
		}
	}
	subject, err := claimString(claims, "sub", true)
	if err != nil || subject != expectedSubject {
		return nil, fmt.Errorf("OIDC UserInfo subject does not match the ID token")
	}
	return claims, nil
}

func claimString(claims map[string]json.RawMessage, name string, required bool) (string, error) {
	raw, present := claims[name]
	if !present {
		if required {
			return "", fmt.Errorf("OIDC claim %s is required", name)
		}
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", fmt.Errorf("OIDC claim %s is invalid", name)
	}
	return value, nil
}

func claimUnixTime(claims map[string]json.RawMessage, name string) (time.Time, error) {
	raw, present := claims[name]
	if !present {
		return time.Time{}, fmt.Errorf("OIDC claim %s is required", name)
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return time.Time{}, err
	}
	seconds, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, fmt.Errorf("invalid time claim")
	}
	return time.Unix(seconds, 0).UTC(), nil
}
