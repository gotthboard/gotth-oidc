package oidc

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// JOSESigner is the built-in compact-JWS signer. Key remains caller-owned.
// EmbedPublicJWK is required for DPoP and should be false for other JWTs.
type JOSESigner struct {
	SignatureAlgorithm jose.SignatureAlgorithm
	Key                any
	KeyID              string
	EmbedPublicJWK     bool
}

func (signer JOSESigner) Algorithm() string { return string(signer.SignatureAlgorithm) }

// DPoPKeyThumbprint returns the base64url RFC 7638 SHA-256 thumbprint of the
// signer's public key.
func (signer JOSESigner) DPoPKeyThumbprint(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil || signer.Key == nil {
		return "", fmt.Errorf("OIDC DPoP thumbprint input is invalid")
	}
	sourceKey := jose.JSONWebKey{Key: signer.Key}
	key := sourceKey.Public()
	if !key.Valid() || !key.IsPublic() {
		return "", fmt.Errorf("OIDC DPoP signer has no valid public key")
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute OIDC DPoP key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func (signer JOSESigner) SignJWT(ctx context.Context, typ string, claims json.RawMessage) (string, error) {
	if ctx == nil || ctx.Err() != nil || signer.Key == nil || signer.SignatureAlgorithm == "" || len(claims) == 0 || !json.Valid(claims) {
		return "", fmt.Errorf("OIDC JOSE signer input is invalid")
	}
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	options.EmbedJWK = signer.EmbedPublicJWK
	key := signer.Key
	if signer.KeyID != "" {
		key = jose.JSONWebKey{Key: signer.Key, KeyID: signer.KeyID, Use: "sig", Algorithm: string(signer.SignatureAlgorithm)}
	}
	jwsSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: signer.SignatureAlgorithm, Key: key}, options)
	if err != nil {
		return "", fmt.Errorf("construct OIDC JOSE signer: %w", err)
	}
	object, err := jwsSigner.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("sign OIDC JWT: %w", err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize OIDC JWT: %w", err)
	}
	return compact, nil
}

// JOSEDecrypter is the built-in compact-JWE decrypter. The algorithm lists are
// mandatory allowlists; accepting an algorithm merely because a key supports it
// is forbidden.
type JOSEDecrypter struct {
	Key                any
	KeyAlgorithms      []jose.KeyAlgorithm
	ContentEncryptions []jose.ContentEncryption
}

func (decrypter JOSEDecrypter) DecryptJWT(ctx context.Context, compactJWE string) (string, error) {
	if ctx == nil || ctx.Err() != nil || decrypter.Key == nil || len(decrypter.KeyAlgorithms) == 0 || len(decrypter.ContentEncryptions) == 0 || len(compactJWE) > maxOIDCIDTokenBytes {
		return "", fmt.Errorf("OIDC JOSE decrypter input is invalid")
	}
	object, err := jose.ParseEncryptedCompact(compactJWE, decrypter.KeyAlgorithms, decrypter.ContentEncryptions)
	if err != nil {
		return "", fmt.Errorf("parse encrypted OIDC JWT: %w", err)
	}
	plaintext, err := object.Decrypt(decrypter.Key)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxOIDCIDTokenBytes || strings.Count(string(plaintext), ".") != 2 {
		return "", fmt.Errorf("decrypt OIDC JWT failed")
	}
	return string(plaintext), nil
}

func (provider discoveredOIDCProvider) verifyAuthorizationResponseJWT(ctx context.Context, raw string, now time.Time) (AuthorizationResponse, error) {
	if !provider.enableJARM || len(raw) == 0 || len(raw) > maxAuthorizationResponseBytes {
		return AuthorizationResponse{}, fmt.Errorf("OIDC JWT authorization response is not enabled or invalid")
	}
	if strings.Count(raw, ".") == 4 {
		if provider.tokenDecrypter == nil {
			return AuthorizationResponse{}, fmt.Errorf("OIDC JWT authorization response is encrypted but no decrypter is configured")
		}
		decrypted, err := provider.tokenDecrypter.DecryptJWT(ctx, raw)
		if err != nil {
			return AuthorizationResponse{}, fmt.Errorf("decrypt OIDC authorization response failed")
		}
		raw = decrypted
	}
	header, err := parseCompactJWTHeader(raw)
	if err != nil || header.Type != "oauth-authz-resp+jwt" || !containsString(safeSigningAlgorithms(provider.metadata.JARMAlgorithms), header.Algorithm) {
		return AuthorizationResponse{}, fmt.Errorf("OIDC authorization response JWT header is invalid")
	}
	payload, err := provider.keySet.VerifySignature(coreoidc.ClientContext(ctx, provider.httpClient), raw)
	if err != nil {
		return AuthorizationResponse{}, fmt.Errorf("OIDC authorization response JWT signature is invalid")
	}
	var claims struct {
		Issuer      string        `json:"iss"`
		Audience    audienceClaim `json:"aud"`
		ExpiresAt   int64         `json:"exp"`
		IssuedAt    int64         `json:"iat"`
		Code        string        `json:"code"`
		State       string        `json:"state"`
		Error       string        `json:"error"`
		Description string        `json:"error_description"`
		ErrorURI    string        `json:"error_uri"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != provider.issuer || len(claims.Audience) != 1 || claims.Audience[0] != provider.oauth2Config.ClientID || claims.ExpiresAt <= now.Unix() || claims.ExpiresAt > now.Add(10*time.Minute).Unix() || claims.IssuedAt > now.Add(time.Minute).Unix() {
		return AuthorizationResponse{}, fmt.Errorf("OIDC authorization response JWT claims are invalid")
	}
	response := AuthorizationResponse{Code: claims.Code, State: claims.State, Issuer: claims.Issuer}
	if claims.Error != "" {
		if claims.Code != "" {
			return AuthorizationResponse{}, fmt.Errorf("OIDC authorization response JWT combines success and error")
		}
		response.Error = &AuthorizationError{Code: claims.Error, Description: claims.Description, URI: claims.ErrorURI}
		return response, nil
	}
	if claims.Code == "" || claims.State == "" {
		return AuthorizationResponse{}, fmt.Errorf("OIDC authorization response JWT is incomplete")
	}
	return response, nil
}

type jwtHeader struct {
	Algorithm string          `json:"alg"`
	Type      string          `json:"typ"`
	JWK       json.RawMessage `json:"jwk"`
}

func parseCompactJWTHeader(raw string) (jwtHeader, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return jwtHeader{}, fmt.Errorf("JWT is not compact JWS")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(decoded) > 4096 {
		return jwtHeader{}, fmt.Errorf("JWT header is invalid")
	}
	var header jwtHeader
	if err := json.Unmarshal(decoded, &header); err != nil || header.Algorithm == "" {
		return jwtHeader{}, fmt.Errorf("JWT header is invalid")
	}
	return header, nil
}

type audienceClaim []string

func (audience *audienceClaim) UnmarshalJSON(raw []byte) error {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		*audience = audienceClaim{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil || len(multiple) == 0 {
		return fmt.Errorf("invalid audience")
	}
	*audience = audienceClaim(multiple)
	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func safeProofAlgorithms() []string {
	return []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA"}
}
