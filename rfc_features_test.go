package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestRFCOptionalProfileFormPostTokenReturnAndRefresh(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret",
		RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport,
		Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true,
		IdentityPolicy:                     IdentityPolicy{UseUserInfo: true, RequireDisplayName: true, RequireVerifiedEmail: true},
		RequireAuthorizationResponseIssuer: true,
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	maxAge := 5 * time.Minute
	authorization, err := client.BeginContext(context.Background(), AuthorizationOptions{
		ResponseMode: ResponseModeFormPost, MaxAge: &maxAge, ACRValues: []string{"urn:loa:2"},
		Prompt: []string{"consent"}, OfflineAccess: true,
		Claims: json.RawMessage(`{"id_token":{"auth_time":{"essential":true}}}`),
	})
	if err != nil {
		t.Fatalf("BeginContext() returned error: %v", err)
	}
	parsed, _ := url.Parse(authorization.URL)
	if parsed.Query().Get("response_mode") != "form_post" || parsed.Query().Get("max_age") != "300" || parsed.Query().Get("acr_values") != "urn:loa:2" || !strings.Contains(parsed.Query().Get("scope"), "offline_access") {
		t.Fatalf("authorization query = %v", parsed.Query())
	}
	completion, err := client.CompleteTokens(context.Background(), AuthorizationResponse{
		Code: "successful-code", State: parsed.Query().Get("state"), Issuer: harness.issuer, Mode: ResponseModeFormPost,
	}, authorization.Attempt)
	if err != nil {
		t.Fatalf("CompleteTokens() returned error: %v", err)
	}
	if completion.Identity.DisplayName != "UserInfo Name" || completion.Identity.Email == nil || *completion.Identity.Email != "userinfo@example.com" || completion.Tokens.RefreshToken != "refresh-token" {
		t.Fatalf("completion = %+v / %+v", completion.Identity, completion.Tokens)
	}
	refreshed, err := client.Refresh(context.Background(), RefreshRequest{RefreshToken: "refresh-token", ExpectedSubject: "subject-1", Scopes: []string{"openid", "profile"}})
	if err != nil || refreshed.RefreshToken != "refresh-token" || refreshed.AccessToken == "" {
		t.Fatalf("Refresh() = (%+v, %v)", refreshed, err)
	}
}

func TestRFCRequestObjectPARAndJWTClientAuthentication(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	signer := JOSESigner{SignatureAlgorithm: jose.ES256, Key: harness.signingKey, KeyID: "exchange-test-key"}
	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", RedirectURL: "https://forum.example/bb/auth/callback",
		Transport: harness.server.Client().Transport, Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true,
		RequestObjectSigner: signer, EnablePAR: true,
		ClientAuthentication: ClientAuthentication{Method: PrivateKeyJWT, Signer: signer},
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	authorization, err := client.BeginContext(context.Background(), AuthorizationOptions{UsePAR: true, UseRequestObject: true, LoginHint: "member@example.com"})
	if err != nil {
		t.Fatalf("BeginContext() returned error: %v", err)
	}
	parsed, _ := url.Parse(authorization.URL)
	if parsed.Query().Get("request_uri") != "urn:example:par:1" || parsed.Query().Get("client_id") != "gotth-bb" {
		t.Fatalf("PAR authorization URL = %s", authorization.URL)
	}
	harness.mutex.Lock()
	form := cloneValues(harness.parForm)
	harness.mutex.Unlock()
	requestHeader, requestErr := parseCompactJWTHeader(form.Get("request"))
	assertionHeader, assertionErr := parseCompactJWTHeader(form.Get("client_assertion"))
	if requestErr != nil || requestHeader.Type != "oauth-authz-req+jwt" || assertionErr != nil || assertionHeader.Type != "JWT" || form.Get("client_assertion_type") == "" {
		t.Fatalf("PAR form/request headers = %v / %+v / %v / %+v", requestErr, requestHeader, assertionErr, assertionHeader)
	}
}

func TestRFCJARMAndAudienceAuthorizedPartyValidation(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret",
		RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport,
		Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true,
		EnableJARM: true, RequireAuthorizationResponseIssuer: true, TrustedAudiences: []string{"trusted-api"},
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	authorization, err := client.BeginContext(context.Background(), AuthorizationOptions{ResponseMode: ResponseModeJWT})
	if err != nil {
		t.Fatalf("BeginContext() returned error: %v", err)
	}
	parsed, _ := url.Parse(authorization.URL)
	state := parsed.Query().Get("state")
	jarmSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: harness.signingKey}, new(jose.SignerOptions).WithType("oauth-authz-resp+jwt").WithHeader(jose.HeaderKey("kid"), "exchange-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	rawJARM, err := jwt.Signed(jarmSigner).Claims(map[string]any{"iss": harness.issuer, "aud": "gotth-bb", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "code": "successful-code", "state": state}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := client.CompleteResponse(context.Background(), AuthorizationResponse{ResponseJWT: rawJARM, Mode: ResponseModeQuery}, authorization.Attempt)
	if err != nil || identity.Subject != "subject-1" {
		t.Fatalf("JARM completion = (%+v, %v)", identity, err)
	}
	provider := client.provider
	for _, code := range []string{"multi-audience-untrusted", "wrong-azp", "wrong-token-type", "missing-token-type"} {
		if got, err := provider.exchangeInitialLogin(context.Background(), code, harness.material); err == nil || got != (verifiedIdentityClaims{}) {
			t.Fatalf("%s = (%+v, %v), want rejection", code, got, err)
		}
	}
	got, err := provider.exchangeInitialLogin(context.Background(), "multi-audience-trusted", harness.material)
	if err != nil || got.subject != "subject-1" {
		t.Fatalf("trusted multi-audience token = (%+v, %v)", got, err)
	}
}

func TestCallbackParserHandlesQueryFormErrorsAndRejectsAmbiguity(t *testing.T) {
	query := httptest.NewRequest(http.MethodGet, "https://client.example/cb?code=c&state=s&iss=https%3A%2F%2Fissuer.example", nil)
	parsed, err := ParseCallback(query)
	if err != nil || parsed.Code != "c" || parsed.Mode != ResponseModeQuery {
		t.Fatalf("query callback = (%+v, %v)", parsed, err)
	}
	form := url.Values{"code": {"c"}, "state": {"s"}}
	post := httptest.NewRequest(http.MethodPost, "https://client.example/cb", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parsed, err = ParseCallback(post)
	if err != nil || parsed.Mode != ResponseModeFormPost {
		t.Fatalf("form callback = (%+v, %v)", parsed, err)
	}
	errorRequest := httptest.NewRequest(http.MethodGet, "https://client.example/cb?error=access_denied&state=s&error_description=no", nil)
	parsed, err = ParseCallback(errorRequest)
	if err != nil || parsed.Error == nil || parsed.Error.Error() != "OIDC authorization failed: access_denied" {
		t.Fatalf("error callback = (%+v, %v)", parsed, err)
	}
	for _, raw := range []string{
		"https://client.example/cb?code=a&code=b&state=s",
		"https://client.example/cb?code=c&state=s&unknown=x",
		"https://client.example/cb?error=denied",
		"https://client.example/cb?code=c",
	} {
		if got, err := ParseCallback(httptest.NewRequest(http.MethodGet, raw, nil)); err == nil || got != (AuthorizationResponse{}) {
			t.Fatalf("ParseCallback(%q) = (%+v, %v), want rejection", raw, got, err)
		}
	}
}

func TestWebFingerDynamicRegistrationAndManagement(t *testing.T) {
	var deleted atomic.Bool
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/webfinger":
			writer.Header().Set("Content-Type", "application/jrd+json")
			_ = json.NewEncoder(writer).Encode(map[string]any{"subject": request.URL.Query().Get("resource"), "links": []map[string]string{{"rel": issuerRelation, "href": server.URL}}})
		case "/register":
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(map[string]any{"client_id": "dynamic-client", "client_secret": "dynamic-secret", "client_id_issued_at": time.Now().Unix(), "registration_access_token": "management-token", "registration_client_uri": server.URL + "/manage"})
		case "/manage":
			if request.Header.Get("Authorization") != "Bearer management-token" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			if request.Method == http.MethodDelete {
				deleted.Store(true)
				writer.WriteHeader(http.StatusNoContent)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{"client_id": "dynamic-client"})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	issuer, err := DiscoverIssuer(context.Background(), IssuerDiscoveryConfig{Resource: server.URL, Transport: server.Client().Transport})
	if err != nil || issuer != server.URL {
		t.Fatalf("DiscoverIssuer() = (%q, %v)", issuer, err)
	}
	registration, err := RegisterClient(context.Background(), RegistrationConfig{Endpoint: server.URL + "/register", Metadata: json.RawMessage(`{"redirect_uris":["https://client.example/cb"]}`), InitialAccessToken: "initial", Transport: server.Client().Transport})
	if err != nil || registration.ClientID != "dynamic-client" || !strings.Contains(fmt.Sprintf("%+v", registration), "REDACTED") {
		t.Fatalf("RegisterClient() = (%+v, %v)", registration, err)
	}
	if metadata, err := ReadClientRegistration(context.Background(), registration, server.Client().Transport); err != nil || !json.Valid(metadata) {
		t.Fatalf("ReadClientRegistration() = (%s, %v)", metadata, err)
	}
	if metadata, err := UpdateClientRegistration(context.Background(), registration, json.RawMessage(`{"redirect_uris":["https://client.example/new"]}`), server.Client().Transport); err != nil || !json.Valid(metadata) {
		t.Fatalf("UpdateClientRegistration() = (%s, %v)", metadata, err)
	}
	if err := DeleteClientRegistration(context.Background(), registration, server.Client().Transport); err != nil || !deleted.Load() {
		t.Fatalf("DeleteClientRegistration() = %v, deleted=%v", err, deleted.Load())
	}
}

func TestLogoutDPoPMutualTLSAndJOSEEncryption(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	dpopSigner := JOSESigner{SignatureAlgorithm: jose.ES256, Key: harness.signingKey, KeyID: "exchange-test-key", EmbedPublicJWK: true}
	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", RedirectURL: "https://forum.example/bb/auth/callback",
		Transport: harness.server.Client().Transport, AllowInsecureLoopback: true, EnableMutualTLS: true,
		ClientAuthentication: ClientAuthentication{Method: TLSClientAuth}, DPoPSigner: dpopSigner,
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	authorization, err := client.Begin()
	if err != nil {
		t.Fatalf("Begin() with DPoP returned error: %v", err)
	}
	authorizationURL, _ := url.Parse(authorization.URL)
	thumbprint, thumbprintErr := dpopSigner.DPoPKeyThumbprint(context.Background())
	if thumbprintErr != nil || thumbprint == "" || authorizationURL.Query().Get("dpop_jkt") != thumbprint {
		t.Fatalf("DPoP code binding = (%q, %v), URL=%s", thumbprint, thumbprintErr, authorization.URL)
	}
	proof, err := client.DPoPProof(context.Background(), http.MethodGet, "https://api.example/resource?x=1", "access-token", "nonce")
	header, headerErr := parseCompactJWTHeader(proof)
	if err != nil || headerErr != nil || header.Type != "dpop+jwt" || len(header.JWK) == 0 {
		t.Fatalf("DPoPProof() = (%q, %v), header=(%+v, %v)", proof, err, header, headerErr)
	}
	logoutURL, err := client.EndSessionURL(LogoutRequest{ClientID: "gotth-bb", State: "logout-state", PostLogoutRedirectURI: "https://forum.example/logged-out"})
	if err != nil || !strings.Contains(logoutURL, "logout-state") || client.CheckSessionIframe() == "" {
		t.Fatalf("logout/session = (%q, %v, %q)", logoutURL, err, client.CheckSessionIframe())
	}
	frontRequest := httptest.NewRequest(http.MethodGet, "https://forum.example/front?iss="+url.QueryEscape(harness.issuer)+"&sid=session-1", nil)
	front, err := client.ParseFrontChannelLogout(frontRequest)
	if err != nil || front.SessionID != "session-1" {
		t.Fatalf("ParseFrontChannelLogout() = (%+v, %v)", front, err)
	}
	logoutSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: harness.signingKey}, new(jose.SignerOptions).WithType("logout+jwt").WithHeader(jose.HeaderKey("kid"), "exchange-test-key"))
	rawLogout, _ := jwt.Signed(logoutSigner).Claims(map[string]any{"iss": harness.issuer, "aud": "gotth-bb", "iat": time.Now().Unix(), "jti": "logout-jti", "sid": "session-1", "events": map[string]any{backChannelLogoutEvent: map[string]any{}}}).Serialize()
	logout, err := client.VerifyBackChannelLogout(context.Background(), rawLogout)
	if err != nil || logout.SessionID != "session-1" {
		t.Fatalf("VerifyBackChannelLogout() = (%+v, %v)", logout, err)
	}
	if err := client.Revoke(context.Background(), "refresh-token", "refresh_token"); err != nil {
		t.Fatalf("Revoke() returned error: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &rsaKey.PublicKey}, new(jose.EncrypterOptions).WithContentType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, _ := encrypter.Encrypt([]byte("a.b.c"))
	compact, _ := encrypted.CompactSerialize()
	decrypter := JOSEDecrypter{Key: rsaKey, KeyAlgorithms: []jose.KeyAlgorithm{jose.RSA_OAEP_256}, ContentEncryptions: []jose.ContentEncryption{jose.A256GCM}}
	if decrypted, err := decrypter.DecryptJWT(context.Background(), compact); err != nil || decrypted != "a.b.c" {
		t.Fatalf("DecryptJWT() = (%q, %v)", decrypted, err)
	}
}

func TestAuthorizationOptionAndAttemptTamperFailures(t *testing.T) {
	if _, err := validateAuthorizationOptions(AuthorizationOptions{Prompt: []string{"none", "login"}}, IdentityPolicy{}); err == nil {
		t.Fatal("combined prompt=none was accepted")
	}
	negative := -time.Second
	if _, err := validateAuthorizationOptions(AuthorizationOptions{MaxAge: &negative}, IdentityPolicy{}); err == nil {
		t.Fatal("negative max_age was accepted")
	}
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport, Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.Begin()
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorization.URL)
	tampered := authorization.Attempt
	decoded, _ := base64.RawURLEncoding.DecodeString(tampered.ContextCiphertext)
	decoded[len(decoded)-1] ^= 1
	tampered.ContextCiphertext = base64.RawURLEncoding.EncodeToString(decoded)
	if identity, err := client.Complete(context.Background(), parsed.Query().Get("state"), "successful-code", tampered); err == nil || identity != (Identity{}) {
		t.Fatalf("tampered attempt = (%+v, %v)", identity, err)
	}
}

func TestEndpointPolicies(t *testing.T) {
	issuer, _ := url.Parse("https://issuer.example")
	same, _ := url.Parse("https://issuer.example/token?tenant=1")
	other, _ := url.Parse("https://tokens.example/token")
	if err := SameOriginEndpoints.AllowEndpoint(EndpointToken, issuer, same); err != nil {
		t.Fatalf("same-origin endpoint rejected: %v", err)
	}
	if err := SameOriginEndpoints.AllowEndpoint(EndpointToken, issuer, other); err == nil {
		t.Fatal("split-origin endpoint accepted by strict policy")
	}
	if err := HTTPSAnyOriginEndpoints.AllowEndpoint(EndpointToken, issuer, other); err != nil {
		t.Fatalf("HTTPS endpoint rejected: %v", err)
	}
	if err := (EndpointPolicyFunc(nil)).AllowEndpoint(EndpointToken, issuer, other); err == nil {
		t.Fatal("nil endpoint policy accepted")
	}
	if err := HTTPSAnyOriginEndpoints.AllowEndpoint(EndpointToken, issuer, nil); err == nil {
		t.Fatal("nil HTTPS endpoint accepted")
	}
	if !endpointSupports(nil, "query", "query") || endpointSupports([]string{"form_post"}, "query") {
		t.Fatal("endpoint capability defaults are incorrect")
	}
}
