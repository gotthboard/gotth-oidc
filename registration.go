package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

// RegistrationConfig performs one OpenID Connect Dynamic Client Registration
// request. Metadata is the complete standards-defined registration object;
// callers retain policy over requested redirect URIs and key material.
type RegistrationConfig struct {
	Endpoint              string
	Metadata              json.RawMessage
	InitialAccessToken    string
	Transport             http.RoundTripper
	AllowInsecureLoopback bool
}

// ClientRegistration contains registration credentials. Formatting is always
// redacted because the client secret and registration access token are bearer
// credentials.
type ClientRegistration struct {
	ClientID                string
	ClientSecret            string
	ClientIDIssuedAt        time.Time
	ClientSecretExpiresAt   time.Time
	RegistrationAccessToken string
	RegistrationClientURI   string
	Metadata                json.RawMessage
}

func (registration ClientRegistration) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED OIDC CLIENT REGISTRATION]")
}

// RegisterClient performs one bounded dynamic registration request.
func RegisterClient(ctx context.Context, config RegistrationConfig) (ClientRegistration, error) {
	if ctx == nil || len(config.Metadata) == 0 || len(config.Metadata) > 64<<10 || !json.Valid(config.Metadata) || len(config.InitialAccessToken) > 64<<10 {
		return ClientRegistration{}, fmt.Errorf("OIDC registration input is invalid")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(config.Metadata, &object); err != nil || object == nil || len(object) == 0 {
		return ClientRegistration{}, fmt.Errorf("OIDC registration metadata must be a nonempty JSON object")
	}
	endpoint, err := validateNetworkURL("OIDC registration endpoint", config.Endpoint, config.AllowInsecureLoopback, true, true)
	if err != nil {
		return ClientRegistration{}, err
	}
	base := config.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client := boundedOIDCHTTPClient(base, map[string]bool{endpoint.Scheme + "://" + endpoint.Host: true})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(config.Metadata))
	if err != nil {
		return ClientRegistration{}, fmt.Errorf("construct OIDC registration request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if config.InitialAccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+config.InitialAccessToken)
	}
	response, err := client.Do(request)
	if err != nil {
		return ClientRegistration{}, fmt.Errorf("OIDC registration request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDirectResponseBytes+1))
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || len(body) > maxDirectResponseBytes || mediaType != "application/json" || (response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK) {
		return ClientRegistration{}, fmt.Errorf("OIDC registration response failed")
	}
	var wire struct {
		ClientID                string `json:"client_id"`
		ClientSecret            string `json:"client_secret"`
		ClientIDIssuedAt        int64  `json:"client_id_issued_at"`
		ClientSecretExpiresAt   int64  `json:"client_secret_expires_at"`
		RegistrationAccessToken string `json:"registration_access_token"`
		RegistrationClientURI   string `json:"registration_client_uri"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.ClientID == "" || len(wire.ClientID) > 4096 || len(wire.ClientSecret) > 64<<10 || len(wire.RegistrationAccessToken) > 64<<10 {
		return ClientRegistration{}, fmt.Errorf("OIDC registration response is invalid")
	}
	result := ClientRegistration{ClientID: wire.ClientID, ClientSecret: wire.ClientSecret, RegistrationAccessToken: wire.RegistrationAccessToken, RegistrationClientURI: wire.RegistrationClientURI, Metadata: append(json.RawMessage(nil), body...)}
	if wire.ClientIDIssuedAt > 0 {
		result.ClientIDIssuedAt = time.Unix(wire.ClientIDIssuedAt, 0).UTC()
	}
	if wire.ClientSecretExpiresAt > 0 {
		result.ClientSecretExpiresAt = time.Unix(wire.ClientSecretExpiresAt, 0).UTC()
	}
	if wire.RegistrationClientURI != "" {
		if _, err := validateNetworkURL("OIDC registration client URI", wire.RegistrationClientURI, config.AllowInsecureLoopback, true, true); err != nil || wire.RegistrationAccessToken == "" {
			return ClientRegistration{}, fmt.Errorf("OIDC registration management credentials are invalid")
		}
	}
	return result, nil
}

// ReadClientRegistration retrieves the current registration metadata.
func ReadClientRegistration(ctx context.Context, registration ClientRegistration, transport http.RoundTripper) (json.RawMessage, error) {
	return manageClientRegistration(ctx, http.MethodGet, registration, nil, transport)
}

// UpdateClientRegistration replaces registration metadata and returns the
// server's complete updated representation.
func UpdateClientRegistration(ctx context.Context, registration ClientRegistration, metadata json.RawMessage, transport http.RoundTripper) (json.RawMessage, error) {
	if len(metadata) == 0 || len(metadata) > 64<<10 || !json.Valid(metadata) {
		return nil, fmt.Errorf("OIDC registration update metadata is invalid")
	}
	return manageClientRegistration(ctx, http.MethodPut, registration, metadata, transport)
}

// DeleteClientRegistration deletes a dynamically registered client.
func DeleteClientRegistration(ctx context.Context, registration ClientRegistration, transport http.RoundTripper) error {
	_, err := manageClientRegistration(ctx, http.MethodDelete, registration, nil, transport)
	return err
}

func manageClientRegistration(ctx context.Context, method string, registration ClientRegistration, metadata json.RawMessage, transport http.RoundTripper) (json.RawMessage, error) {
	if ctx == nil || registration.RegistrationAccessToken == "" || len(registration.RegistrationAccessToken) > 64<<10 {
		return nil, fmt.Errorf("OIDC registration management credentials are invalid")
	}
	endpoint, err := validateNetworkURL("OIDC registration client URI", registration.RegistrationClientURI, false, true, true)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := boundedOIDCHTTPClient(transport, map[string]bool{endpoint.Scheme + "://" + endpoint.Host: true})
	var body io.Reader
	if len(metadata) != 0 {
		body = bytes.NewReader(metadata)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("construct OIDC registration management request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+registration.RegistrationAccessToken)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("OIDC registration management request failed")
	}
	defer response.Body.Close()
	if method == http.MethodDelete {
		if response.StatusCode != http.StatusNoContent {
			return nil, fmt.Errorf("OIDC registration deletion returned HTTP %d", response.StatusCode)
		}
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC registration management returned HTTP %d", response.StatusCode)
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "application/json" {
		return nil, fmt.Errorf("OIDC registration management response has an invalid content type")
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, maxDirectResponseBytes+1))
	if err != nil || len(result) > maxDirectResponseBytes || !json.Valid(result) {
		return nil, fmt.Errorf("OIDC registration management response is invalid")
	}
	return json.RawMessage(result), nil
}
