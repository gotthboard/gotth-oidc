package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const issuerRelation = "http://openid.net/specs/connect/1.0/issuer"

// IssuerDiscoveryConfig controls optional OpenID Provider issuer discovery via
// WebFinger. Resource may be an acct URI, e-mail address, HTTPS URL, or host.
type IssuerDiscoveryConfig struct {
	Resource              string
	Transport             http.RoundTripper
	AllowInsecureLoopback bool
}

// DiscoverIssuer performs bounded WebFinger issuer discovery and returns one
// exact issuer URL. It does not create a Client or register one.
func DiscoverIssuer(ctx context.Context, config IssuerDiscoveryConfig) (string, error) {
	if ctx == nil || config.Resource == "" || len(config.Resource) > 4096 {
		return "", fmt.Errorf("OIDC issuer-discovery input is invalid")
	}
	resource, authority, err := normalizeWebFingerResource(config.Resource)
	if err != nil {
		return "", err
	}
	scheme := "https"
	if config.AllowInsecureLoopback {
		authorityURL, _ := url.Parse("//" + authority)
		if parsed := net.ParseIP(authorityURL.Hostname()); parsed != nil && parsed.IsLoopback() {
			scheme = "http"
		}
	}
	endpoint := &url.URL{Scheme: scheme, Host: authority, Path: "/.well-known/webfinger"}
	query := endpoint.Query()
	query.Set("resource", resource)
	query.Set("rel", issuerRelation)
	endpoint.RawQuery = query.Encode()
	base := config.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client := boundedOIDCHTTPClient(base, map[string]bool{endpoint.Scheme + "://" + endpoint.Host: true})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("construct OIDC WebFinger request: %w", err)
	}
	request.Header.Set("Accept", "application/jrd+json, application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("OIDC WebFinger request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC WebFinger returned HTTP %d", response.StatusCode)
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "application/jrd+json" && mediaType != "application/json" {
		return "", fmt.Errorf("OIDC WebFinger response has an invalid content type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, oidcHTTPResponseMaxBytes+1))
	if err != nil || len(body) > oidcHTTPResponseMaxBytes {
		return "", fmt.Errorf("OIDC WebFinger response is unreadable or oversized")
	}
	var document struct {
		Subject string `json:"subject"`
		Links   []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	if err := json.Unmarshal(body, &document); err != nil || document.Subject != resource {
		return "", fmt.Errorf("OIDC WebFinger response is invalid")
	}
	issuer := ""
	for _, link := range document.Links {
		if link.Rel == issuerRelation {
			if issuer != "" || link.Href == "" {
				return "", fmt.Errorf("OIDC WebFinger returns an ambiguous issuer")
			}
			issuer = link.Href
		}
	}
	if issuer == "" {
		return "", fmt.Errorf("OIDC WebFinger omits the issuer relation")
	}
	parsed, err := validateNetworkURL("OIDC discovered issuer", issuer, config.AllowInsecureLoopback, false, false)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func normalizeWebFingerResource(raw string) (string, string, error) {
	if strings.ContainsAny(raw, "\r\n\t ") {
		return "", "", fmt.Errorf("OIDC WebFinger resource is invalid")
	}
	if strings.HasPrefix(raw, "acct:") {
		account := strings.TrimPrefix(raw, "acct:")
		at := strings.LastIndexByte(account, '@')
		if at <= 0 || at == len(account)-1 {
			return "", "", fmt.Errorf("OIDC WebFinger account resource is invalid")
		}
		return raw, account[at+1:], nil
	}
	if !strings.Contains(raw, "://") && strings.Count(raw, "@") == 1 {
		return normalizeWebFingerResource("acct:" + raw)
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return "", "", fmt.Errorf("OIDC WebFinger URL resource is invalid")
		}
		return parsed.String(), parsed.Host, nil
	}
	parsed, err := url.Parse("https://" + raw)
	if err != nil || parsed.Host == "" || parsed.Path != "" {
		return "", "", fmt.Errorf("OIDC WebFinger host resource is invalid")
	}
	return parsed.String(), parsed.Host, nil
}
