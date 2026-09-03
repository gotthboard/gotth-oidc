package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Revoke revokes one access or refresh token when the provider advertises RFC
// 7009. Empty token-type hints are allowed; other hints are bounded.
func (client *Client) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	if client == nil || client.provider.metadata.RevocationEndpoint == "" || token == "" || len(token) > 64<<10 || len(tokenTypeHint) > 128 {
		return fmt.Errorf("OIDC revocation input or endpoint is invalid")
	}
	endpoint := client.provider.metadata.RevocationEndpoint
	if client.provider.enableMutualTLS && client.provider.metadata.MTLSEndpointAliases.RevocationEndpoint != "" {
		endpoint = client.provider.metadata.MTLSEndpointAliases.RevocationEndpoint
	}
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	request, err := client.provider.newAuthenticatedFormRequest(ctx, endpoint, form, client.clock().UTC(), "")
	if err != nil {
		return err
	}
	response, err := client.provider.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("OIDC token revocation failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("OIDC token revocation returned HTTP %d", response.StatusCode)
	}
	return nil
}

// DPoPProof creates a proof for a protected-resource request. The configured
// signer must embed its public JWK. Nonce storage/retry policy remains with the
// HTTP client that owns the protected-resource request.
func (client *Client) DPoPProof(ctx context.Context, method, targetURI, accessToken, nonce string) (string, error) {
	if client == nil || client.provider.dpopSigner == nil {
		return "", fmt.Errorf("OIDC DPoP is not configured")
	}
	parsed, err := url.Parse(targetURI)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("OIDC DPoP target URI is invalid")
	}
	return client.provider.dpopProof(ctx, method, parsed.String(), accessToken, nonce, client.clock().UTC())
}
