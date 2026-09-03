package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	attemptContextVersion    = 1
	attemptContextMaxBytes   = 32 << 10
	attemptContextKeyLabel   = "gotth-oidc/oidc-login-attempt/context/aes-256-gcm/v1"
	attemptContextNonceLabel = "gotth-oidc/oidc-login-attempt/context/nonce/v1"
)

type attemptContext struct {
	Version               int          `json:"version"`
	Issuer                string       `json:"issuer"`
	ClientID              string       `json:"client_id"`
	RedirectURL           string       `json:"redirect_uri"`
	ResponseMode          ResponseMode `json:"response_mode"`
	RequireResponseIssuer bool         `json:"require_response_issuer"`
	StartedAtUnix         int64        `json:"started_at"`
	MaxAgeSeconds         *int64       `json:"max_age,omitempty"`
	ACRValues             []string     `json:"acr_values,omitempty"`
	UseUserInfo           bool         `json:"use_userinfo"`
	RequireName           bool         `json:"require_name"`
	RequireEmail          bool         `json:"require_email"`
	OfflineAccess         bool         `json:"offline_access"`
}

func sealAttemptContext(stateValue string, stateHash [sha256.Size]byte, value attemptContext) ([]byte, error) {
	state, err := base64.RawURLEncoding.Strict().DecodeString(stateValue)
	defer clear(state)
	if err != nil || len(state) != loginSecretBytes {
		return nil, fmt.Errorf("login state has an invalid encoding or length")
	}
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > attemptContextMaxBytes {
		return nil, fmt.Errorf("OIDC attempt context is invalid")
	}
	defer clear(payload)
	key, nonce := deriveAttemptContextKey(state)
	defer clear(key[:])
	defer clear(nonce[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("construct OIDC attempt context cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("construct OIDC attempt context AEAD: %w", err)
	}
	sealed := aead.Seal(nil, nonce[:], payload, stateHash[:])
	return append([]byte{attemptContextVersion}, sealed...), nil
}

func openAttemptContext(stateValue string, stateHash [sha256.Size]byte, envelope []byte) (attemptContext, error) {
	if len(envelope) < 1+loginGCMTagBytes || len(envelope) > 1+attemptContextMaxBytes+loginGCMTagBytes || envelope[0] != attemptContextVersion {
		return attemptContext{}, fmt.Errorf("OIDC attempt context has an invalid format")
	}
	state, err := base64.RawURLEncoding.Strict().DecodeString(stateValue)
	defer clear(state)
	if err != nil || len(state) != loginSecretBytes {
		return attemptContext{}, fmt.Errorf("login state has an invalid encoding or length")
	}
	computedHash := sha256.Sum256([]byte(stateValue))
	if subtle.ConstantTimeCompare(computedHash[:], stateHash[:]) != 1 {
		return attemptContext{}, fmt.Errorf("login state does not match the stored attempt")
	}
	key, nonce := deriveAttemptContextKey(state)
	defer clear(key[:])
	defer clear(nonce[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return attemptContext{}, fmt.Errorf("construct OIDC attempt context cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return attemptContext{}, fmt.Errorf("construct OIDC attempt context AEAD: %w", err)
	}
	payload, err := aead.Open(nil, nonce[:], envelope[1:], stateHash[:])
	if err != nil {
		return attemptContext{}, fmt.Errorf("OIDC attempt context authentication failed")
	}
	defer clear(payload)
	var value attemptContext
	if err := json.Unmarshal(payload, &value); err != nil || value.Version != attemptContextVersion || value.StartedAtUnix <= 0 {
		return attemptContext{}, fmt.Errorf("OIDC attempt context is invalid")
	}
	return value, nil
}

func deriveAttemptContextKey(state []byte) ([sha256.Size]byte, [loginGCMNonceBytes]byte) {
	var key [sha256.Size]byte
	mac := hmac.New(sha256.New, state)
	_, _ = mac.Write([]byte(attemptContextKeyLabel))
	mac.Sum(key[:0])
	var nonce [loginGCMNonceBytes]byte
	mac = hmac.New(sha256.New, state)
	_, _ = mac.Write([]byte(attemptContextNonceLabel))
	copy(nonce[:], mac.Sum(nil))
	return key, nonce
}

func (value attemptContext) validateFor(client *Client) error {
	if client == nil || value.Issuer != client.provider.issuer || value.ClientID != client.provider.oauth2Config.ClientID || value.RedirectURL != client.provider.oauth2Config.RedirectURL {
		return fmt.Errorf("OIDC attempt belongs to a different relying-party binding")
	}
	switch value.ResponseMode {
	case ResponseModeQuery, ResponseModeFormPost, ResponseModeJWT, ResponseModeQueryJWT, ResponseModeFormJWT:
	default:
		return fmt.Errorf("OIDC attempt response mode is invalid")
	}
	if value.MaxAgeSeconds != nil && (*value.MaxAgeSeconds < 0 || *value.MaxAgeSeconds > int64((365*24*time.Hour)/time.Second)) {
		return fmt.Errorf("OIDC attempt max_age is invalid")
	}
	return nil
}
