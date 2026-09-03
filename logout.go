package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

const backChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutRequest configures an RP-initiated logout URL.
type LogoutRequest struct {
	IDTokenHint           string
	LogoutHint            string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	UILocales             []string
}

// EndSessionURL constructs a validated RP-initiated logout URL.
func (client *Client) EndSessionURL(request LogoutRequest) (string, error) {
	if client == nil || client.provider.metadata.EndSessionEndpoint == "" {
		return "", fmt.Errorf("OIDC provider does not advertise RP-initiated logout")
	}
	endpoint, err := url.Parse(client.provider.metadata.EndSessionEndpoint)
	if err != nil {
		return "", fmt.Errorf("OIDC end-session endpoint is invalid")
	}
	for name, value := range map[string]string{"id_token_hint": request.IDTokenHint, "logout_hint": request.LogoutHint, "client_id": request.ClientID, "post_logout_redirect_uri": request.PostLogoutRedirectURI, "state": request.State} {
		if len(value) > 64<<10 || strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("OIDC logout %s is invalid", name)
		}
	}
	if request.ClientID != "" && request.ClientID != client.provider.oauth2Config.ClientID {
		return "", fmt.Errorf("OIDC logout client ID is invalid")
	}
	if request.PostLogoutRedirectURI != "" {
		if _, err := validateNetworkURL("OIDC post-logout redirect URI", request.PostLogoutRedirectURI, false, true, false); err != nil {
			return "", err
		}
		if request.IDTokenHint == "" && request.ClientID == "" {
			return "", fmt.Errorf("OIDC post-logout redirect requires an ID-token hint or client ID")
		}
	}
	query := endpoint.Query()
	if request.IDTokenHint != "" {
		query.Set("id_token_hint", request.IDTokenHint)
	}
	if request.LogoutHint != "" {
		query.Set("logout_hint", request.LogoutHint)
	}
	if request.ClientID != "" {
		query.Set("client_id", request.ClientID)
	}
	if request.PostLogoutRedirectURI != "" {
		query.Set("post_logout_redirect_uri", request.PostLogoutRedirectURI)
	}
	if request.State != "" {
		query.Set("state", request.State)
	}
	if len(request.UILocales) != 0 {
		locales, err := validateAuthorizationOptions(AuthorizationOptions{UILocales: request.UILocales}, IdentityPolicy{})
		if err != nil {
			return "", err
		}
		query.Set("ui_locales", strings.Join(locales.uiLocales, " "))
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

// LogoutToken identifies the session or subject named by a verified
// Back-Channel Logout token.
type LogoutToken struct {
	Issuer    string
	Subject   string
	SessionID string
	JWTID     string
	IssuedAt  time.Time
}

// VerifyBackChannelLogout verifies a purpose-bound Back-Channel Logout token.
// Replay detection for JWTID remains caller-owned persistent state.
func (client *Client) VerifyBackChannelLogout(ctx context.Context, raw string) (LogoutToken, error) {
	if client == nil || !client.provider.metadata.BackChannelLogoutSupported || len(raw) == 0 || len(raw) > maxOIDCIDTokenBytes {
		return LogoutToken{}, fmt.Errorf("OIDC back-channel logout is unavailable or invalid")
	}
	header, err := parseCompactJWTHeader(raw)
	if err != nil || header.Type != "logout+jwt" || !containsString(safeSigningAlgorithms(client.provider.metadata.Algorithms), header.Algorithm) {
		return LogoutToken{}, fmt.Errorf("OIDC logout token header is invalid")
	}
	payload, err := client.provider.keySet.VerifySignature(coreoidc.ClientContext(ctx, client.provider.httpClient), raw)
	if err != nil {
		return LogoutToken{}, fmt.Errorf("OIDC logout token signature is invalid")
	}
	var claims struct {
		Issuer    string                     `json:"iss"`
		Audience  audienceClaim              `json:"aud"`
		IssuedAt  int64                      `json:"iat"`
		JWTID     string                     `json:"jti"`
		Subject   string                     `json:"sub"`
		SessionID string                     `json:"sid"`
		Nonce     json.RawMessage            `json:"nonce"`
		Events    map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Issuer != client.provider.issuer || !containsString([]string(claims.Audience), client.provider.oauth2Config.ClientID) || claims.IssuedAt <= 0 || claims.JWTID == "" || len(claims.Nonce) != 0 || (claims.Subject == "" && claims.SessionID == "") {
		return LogoutToken{}, fmt.Errorf("OIDC logout token claims are invalid")
	}
	event, present := claims.Events[backChannelLogoutEvent]
	var eventObject map[string]json.RawMessage
	if !present || json.Unmarshal(event, &eventObject) != nil || eventObject == nil || len(eventObject) != 0 {
		return LogoutToken{}, fmt.Errorf("OIDC logout token event is invalid")
	}
	now := client.clock().UTC()
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	if issuedAt.After(now.Add(time.Minute)) || now.Sub(issuedAt) > 10*time.Minute {
		return LogoutToken{}, fmt.Errorf("OIDC logout token is outside the accepted time window")
	}
	return LogoutToken{Issuer: claims.Issuer, Subject: claims.Subject, SessionID: claims.SessionID, JWTID: claims.JWTID, IssuedAt: issuedAt}, nil
}

// FrontChannelLogout identifies a validated front-channel logout notification.
type FrontChannelLogout struct {
	Issuer    string
	SessionID string
}

func (client *Client) ParseFrontChannelLogout(request *http.Request) (FrontChannelLogout, error) {
	if client == nil || !client.provider.metadata.FrontChannelLogoutSupported || request == nil || request.URL == nil || request.Method != http.MethodGet {
		return FrontChannelLogout{}, fmt.Errorf("OIDC front-channel logout is unavailable or invalid")
	}
	query := request.URL.Query()
	if len(query) < 1 || len(query) > 2 || len(query["iss"]) != 1 || query.Get("iss") != client.provider.issuer || len(query.Get("sid")) > 4096 {
		return FrontChannelLogout{}, fmt.Errorf("OIDC front-channel logout parameters are invalid")
	}
	if _, present := query["sid"]; present && (len(query["sid"]) != 1 || query.Get("sid") == "") {
		return FrontChannelLogout{}, fmt.Errorf("OIDC front-channel logout parameters are invalid")
	}
	if client.provider.metadata.FrontChannelLogoutSessionRequired && query.Get("sid") == "" {
		return FrontChannelLogout{}, fmt.Errorf("OIDC front-channel logout parameters are invalid")
	}
	return FrontChannelLogout{Issuer: query.Get("iss"), SessionID: query.Get("sid")}, nil
}

// CheckSessionIframe returns the validated OpenID Connect Session Management
// iframe endpoint when the provider advertises one.
func (client *Client) CheckSessionIframe() string {
	if client == nil {
		return ""
	}
	return client.provider.metadata.CheckSessionIframe
}
