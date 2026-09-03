package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

type failingJWTSigner struct {
	algorithm string
}

type staticJWTDecrypter struct {
	value string
	err   error
}

func (decrypter staticJWTDecrypter) DecryptJWT(context.Context, string) (string, error) {
	return decrypter.value, decrypter.err
}

func (signer failingJWTSigner) Algorithm() string { return signer.algorithm }
func (failingJWTSigner) SignJWT(context.Context, string, json.RawMessage) (string, error) {
	return "", errors.New("signing stopped")
}

func TestAuthorizationOptionsRejectMalformedOptionalValues(t *testing.T) {
	tooLongClaims := json.RawMessage(`{"x":"` + strings.Repeat("x", 16<<10) + `"}`)
	negative := -time.Second
	fractional := time.Second + time.Nanosecond
	tooLong := 366 * 24 * time.Hour
	for _, test := range []AuthorizationOptions{
		{Scopes: make([]string, 33)},
		{Scopes: []string{"openid", "openid"}},
		{Scopes: []string{"bad scope"}},
		{Prompt: []string{"none", "login"}},
		{ACRValues: []string{"bad\nacr"}},
		{UILocales: []string{"en", "en"}},
		{ClaimsLocales: []string{"bad locale"}},
		{LoginHint: "bad\nhint"},
		{IDTokenHint: strings.Repeat("x", 4097)},
		{MaxAge: &negative},
		{MaxAge: &fractional},
		{MaxAge: &tooLong},
		{Claims: json.RawMessage(`[]`)},
		{Claims: json.RawMessage(`{`)},
		{Claims: tooLongClaims},
		{ResponseMode: "invented"},
	} {
		if got, err := validateAuthorizationOptions(test, IdentityPolicy{}); err == nil || got.responseMode != "" {
			t.Fatalf("validateAuthorizationOptions(%+v) = (%+v, %v), want zero/error", test, got, err)
		}
	}
	validated, err := validateAuthorizationOptions(AuthorizationOptions{Scopes: []string{"profile"}}, IdentityPolicy{})
	if err != nil || len(validated.scopes) != 2 || validated.scopes[0] != "openid" {
		t.Fatalf("openid scope insertion = (%v, %v)", validated.scopes, err)
	}
}

func TestCallbackParserRejectsMalformedTransportsAndValues(t *testing.T) {
	oversized := strings.Repeat("x", maxAuthorizationResponseBytes+1)
	requests := []*http.Request{
		nil,
		{Method: http.MethodGet},
		httptest.NewRequest(http.MethodPut, "https://client.example/cb", nil),
		httptest.NewRequest(http.MethodGet, "https://client.example/cb?state=s&code="+oversized, nil),
		httptest.NewRequest(http.MethodGet, "https://client.example/cb?state=s&code=a%0A", nil),
		httptest.NewRequest(http.MethodGet, "https://client.example/cb?state=s&response=j&code=c", nil),
		httptest.NewRequest(http.MethodGet, "https://client.example/cb?state=s&error=denied&code=c", nil),
	}
	badType := httptest.NewRequest(http.MethodPost, "https://client.example/cb", strings.NewReader("code=c&state=s"))
	badType.Header.Set("Content-Type", "application/json")
	requests = append(requests, badType)
	mixed := httptest.NewRequest(http.MethodPost, "https://client.example/cb?x=1", strings.NewReader("code=c&state=s"))
	mixed.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	requests = append(requests, mixed)
	for index, request := range requests {
		if got, err := ParseCallback(request); err == nil || got != (AuthorizationResponse{}) {
			t.Fatalf("request %d = (%+v, %v), want zero/error", index, got, err)
		}
	}
	var nilAuthorizationError *AuthorizationError
	if nilAuthorizationError.Error() != "OIDC authorization failed" || (&AuthorizationError{}).Error() != "OIDC authorization failed" {
		t.Fatal("empty authorization errors are not redacted")
	}
}

func TestResponseModeValidationRejectsMismatches(t *testing.T) {
	for _, test := range []struct {
		expected ResponseMode
		response AuthorizationResponse
	}{
		{ResponseModeQuery, AuthorizationResponse{Mode: ResponseModeFormPost}},
		{ResponseModeFormPost, AuthorizationResponse{Mode: ResponseModeQuery}},
		{ResponseModeJWT, AuthorizationResponse{Mode: ResponseModeQuery}},
		{ResponseModeQueryJWT, AuthorizationResponse{Mode: ResponseModeFormPost, ResponseJWT: "x"}},
		{ResponseModeFormJWT, AuthorizationResponse{Mode: ResponseModeQuery, ResponseJWT: "x"}},
		{"bad", AuthorizationResponse{}},
	} {
		if err := validateResponseMode(test.expected, test.response); err == nil {
			t.Fatalf("validateResponseMode(%q, %+v) accepted mismatch", test.expected, test.response)
		}
	}
}

func TestWebFingerResourceNormalization(t *testing.T) {
	for _, test := range []struct {
		raw, resource, authority string
	}{
		{"acct:user@example.com", "acct:user@example.com", "example.com"},
		{"user@example.com", "acct:user@example.com", "example.com"},
		{"https://example.com/user", "https://example.com/user", "example.com"},
		{"example.com", "https://example.com", "example.com"},
	} {
		resource, authority, err := normalizeWebFingerResource(test.raw)
		if err != nil || resource != test.resource || authority != test.authority {
			t.Fatalf("normalizeWebFingerResource(%q) = (%q, %q, %v)", test.raw, resource, authority, err)
		}
	}
	for _, raw := range []string{"", "acct:x", "acct:@example.com", "bad host/path", "ftp://example.com/x", "https://user@example.com/x"} {
		if resource, authority, err := normalizeWebFingerResource(raw); err == nil || resource != "" || authority != "" {
			t.Fatalf("normalizeWebFingerResource(%q) = (%q, %q, %v), want zero/error", raw, resource, authority, err)
		}
	}
}

func TestDiscoverIssuerRejectsBadResponses(t *testing.T) {
	for _, mode := range []string{"status", "content-type", "subject", "ambiguous", "missing", "invalid-json"} {
		t.Run(mode, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if mode == "status" {
					writer.WriteHeader(http.StatusBadGateway)
					return
				}
				writer.Header().Set("Content-Type", "application/jrd+json")
				if mode == "content-type" {
					writer.Header().Set("Content-Type", "text/plain")
				}
				resource := request.URL.Query().Get("resource")
				switch mode {
				case "subject":
					resource = "acct:other@example.com"
				case "invalid-json":
					_, _ = writer.Write([]byte("{"))
					return
				}
				links := []map[string]string{}
				if mode != "missing" {
					links = append(links, map[string]string{"rel": issuerRelation, "href": server.URL})
				}
				if mode == "ambiguous" {
					links = append(links, map[string]string{"rel": issuerRelation, "href": server.URL + "/other"})
				}
				_ = json.NewEncoder(writer).Encode(map[string]any{"subject": resource, "links": links})
			}))
			defer server.Close()
			if issuer, err := DiscoverIssuer(context.Background(), IssuerDiscoveryConfig{Resource: server.URL, Transport: server.Client().Transport}); err == nil || issuer != "" {
				t.Fatalf("DiscoverIssuer(%s) = (%q, %v), want zero/error", mode, issuer, err)
			}
		})
	}
	if issuer, err := DiscoverIssuer(nil, IssuerDiscoveryConfig{}); err == nil || issuer != "" {
		t.Fatalf("DiscoverIssuer(nil) = (%q, %v)", issuer, err)
	}
}

func TestDiscoverIssuerAllowsExplicitLoopbackHTTP(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/jrd+json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"subject": request.URL.Query().Get("resource"), "links": []map[string]string{{"rel": issuerRelation, "href": server.URL}}})
	}))
	defer server.Close()
	issuer, err := DiscoverIssuer(context.Background(), IssuerDiscoveryConfig{Resource: server.URL, AllowInsecureLoopback: true})
	if err != nil || issuer != server.URL {
		t.Fatalf("loopback WebFinger = (%q, %v)", issuer, err)
	}
}

func TestClientAuthenticationValidation(t *testing.T) {
	metadata := providerMetadata{
		TokenAuthMethods:     []string{"none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"},
		TokenAuthSigningAlgs: []string{"ES256", "HS256"},
	}
	keySigner := failingJWTSigner{algorithm: "ES256"}
	for _, config := range []Config{
		{ClientAuthentication: ClientAuthentication{Method: ClientAuthNone}},
		{ClientSecret: "secret", ClientAuthentication: ClientAuthentication{Method: ClientSecretBasic}},
		{ClientSecret: "secret", ClientAuthentication: ClientAuthentication{Method: ClientSecretPost}},
		{ClientSecret: strings.Repeat("s", 32), ClientAuthentication: ClientAuthentication{Method: ClientSecretJWT}},
		{ClientAuthentication: ClientAuthentication{Method: PrivateKeyJWT, Signer: keySigner}},
		{EnableMutualTLS: true, ClientAuthentication: ClientAuthentication{Method: TLSClientAuth}},
		{EnableMutualTLS: true, ClientAuthentication: ClientAuthentication{Method: SelfSignedTLSClientAuth}},
	} {
		if _, err := validateClientAuthentication(config, metadata); err != nil {
			t.Fatalf("validateClientAuthentication(%+v) rejected supported method: %v", config.ClientAuthentication, err)
		}
	}
	for _, config := range []Config{
		{ClientSecret: "secret", ClientAuthentication: ClientAuthentication{Method: ClientAuthNone}},
		{ClientAuthentication: ClientAuthentication{Method: ClientSecretBasic}},
		{ClientAuthentication: ClientAuthentication{Method: ClientSecretPost}},
		{ClientSecret: "short", ClientAuthentication: ClientAuthentication{Method: ClientSecretJWT}},
		{ClientAuthentication: ClientAuthentication{Method: PrivateKeyJWT}},
		{ClientAuthentication: ClientAuthentication{Method: PrivateKeyJWT, Signer: failingJWTSigner{algorithm: "RS512"}}},
		{ClientAuthentication: ClientAuthentication{Method: TLSClientAuth}},
		{ClientAuthentication: ClientAuthentication{Method: "garbage"}},
	} {
		if _, err := validateClientAuthentication(config, metadata); err == nil {
			t.Fatalf("validateClientAuthentication(%+v) accepted invalid method", config.ClientAuthentication)
		}
	}
	if auth, err := validateClientAuthentication(Config{ClientSecret: "secret"}, providerMetadata{}); err != nil || auth.Method != ClientSecretBasic {
		t.Fatalf("default client authentication = (%+v, %v)", auth, err)
	}
}

func TestRootIssuerAndEndpointQueriesAreAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		origin := "http://" + request.Host
		_, _ = fmt.Fprintf(writer, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`, origin, origin+"/authorize?tenant=one", origin+"/token?tenant=one", origin+"/jwks?tenant=one")
	}))
	defer server.Close()
	client, err := New(context.Background(), Config{IssuerURL: server.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "http://127.0.0.1/callback", Transport: server.Client().Transport, AllowInsecureLoopback: true})
	if err != nil || client.provider.clientAuth.Method != ClientSecretBasic || client.provider.metadata.TokenEndpoint != server.URL+"/token?tenant=one" {
		t.Fatalf("root issuer discovery = (%+v, %v)", client, err)
	}
}

func TestProviderOptionalCapabilityAdmission(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	base := Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/cb", Transport: harness.server.Client().Transport, AllowInsecureLoopback: true}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.RequireAuthorizationResponseIssuer = true },
		func(config *Config) { config.EnablePAR = true },
		func(config *Config) { config.EnableJARM = true },
		func(config *Config) {
			config.EnableMutualTLS = true
			config.ClientAuthentication = ClientAuthentication{Method: TLSClientAuth}
		},
		func(config *Config) {
			config.RequestObjectSigner = JOSESigner{SignatureAlgorithm: jose.ES256, Key: harness.signingKey}
		},
		func(config *Config) {
			config.DPoPSigner = JOSESigner{SignatureAlgorithm: jose.ES256, Key: harness.signingKey, EmbedPublicJWK: true}
		},
	} {
		config := base
		mutate(&config)
		if client, err := New(context.Background(), config); err != nil || client == nil {
			t.Fatalf("optional capability admission = (%+v, %v)", client, err)
		}
	}
	badEncryption := base
	badEncryption.TokenDecrypter = staticJWTDecrypter{value: "x.y.z"}
	if client, err := New(context.Background(), badEncryption); err == nil || client != nil {
		t.Fatalf("unadvertised token encryption = (%+v, %v)", client, err)
	}
	badProof := base
	badProof.DPoPSigner = failingJWTSigner{algorithm: "HS256"}
	if client, err := New(context.Background(), badProof); err == nil || client != nil {
		t.Fatalf("unsafe DPoP algorithm = (%+v, %v)", client, err)
	}
	badProof.DPoPSigner = failingJWTSigner{algorithm: "ES256"}
	if client, err := New(context.Background(), badProof); err == nil || client != nil {
		t.Fatalf("DPoP signer without thumbprint = (%+v, %v)", client, err)
	}
}

func TestJOSEAndEndpointHelperFailures(t *testing.T) {
	if _, err := (JOSESigner{}).SignJWT(context.Background(), "JWT", json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty JOSE signer accepted")
	}
	if _, err := (JOSESigner{}).DPoPKeyThumbprint(context.Background()); err == nil {
		t.Fatal("empty DPoP thumbprint signer accepted")
	}
	if _, err := (failingJWTSigner{}).SignJWT(context.Background(), "JWT", json.RawMessage(`{}`)); err == nil {
		t.Fatal("test signer unexpectedly succeeded")
	}
	if _, err := (JOSEDecrypter{}).DecryptJWT(context.Background(), "x"); err == nil {
		t.Fatal("empty JOSE decrypter accepted")
	}
	for _, raw := range []string{"", "a.b", "!!!!.a.b", "e30.a.b"} {
		if _, err := parseCompactJWTHeader(raw); err == nil {
			t.Fatalf("parseCompactJWTHeader(%q) accepted invalid JWT", raw)
		}
	}
	var audience audienceClaim
	if err := json.Unmarshal([]byte(`"client"`), &audience); err != nil || len(audience) != 1 || audience[0] != "client" {
		t.Fatalf("single audience = (%v, %v)", audience, err)
	}
	if err := json.Unmarshal([]byte(`[]`), &audience); err == nil {
		t.Fatal("empty audience accepted")
	}
	if validDPoPNonce("") || validDPoPNonce("bad nonce") || validDPoPNonce(strings.Repeat("x", 4097)) || !validDPoPNonce("nonce") {
		t.Fatal("DPoP nonce validation is incorrect")
	}
	if got := (endpointError{}).Error(); got != "OIDC endpoint request failed" {
		t.Fatalf("empty endpoint error = %q", got)
	}
	if got := (endpointError{Code: "invalid_request"}).Error(); got != "OIDC endpoint request failed: invalid_request" {
		t.Fatalf("coded endpoint error = %q", got)
	}
	var nilClient *Client
	if nilClient.CheckSessionIframe() != "" {
		t.Fatal("nil client exposes a session iframe")
	}
	if _, err := UpdateClientRegistration(context.Background(), ClientRegistration{}, nil, nil); err == nil {
		t.Fatal("empty registration update accepted")
	}
}

func TestLogoutRejectsInvalidInputsAndTokens(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/cb", Transport: harness.server.Client().Transport, AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []LogoutRequest{
		{ClientID: "wrong"},
		{PostLogoutRedirectURI: "http://example.com/out", ClientID: "gotth-bb"},
		{PostLogoutRedirectURI: "https://forum.example/out"},
		{ClientID: "gotth-bb", State: "bad\nstate"},
		{ClientID: "gotth-bb", UILocales: []string{"bad locale"}},
	} {
		if value, err := client.EndSessionURL(request); err == nil || value != "" {
			t.Fatalf("EndSessionURL(%+v) = (%q, %v), want zero/error", request, value, err)
		}
	}
	if _, err := client.VerifyBackChannelLogout(context.Background(), "bad"); err == nil {
		t.Fatal("invalid logout token accepted")
	}
	for _, raw := range []string{
		"https://forum.example/front?iss=" + url.QueryEscape(harness.issuer) + "&sid=a&extra=x",
		"https://forum.example/front?iss=wrong&sid=a",
		"https://forum.example/front?iss=" + url.QueryEscape(harness.issuer) + "&sid=",
	} {
		if got, err := client.ParseFrontChannelLogout(httptest.NewRequest(http.MethodGet, raw, nil)); err == nil || got != (FrontChannelLogout{}) {
			t.Fatalf("ParseFrontChannelLogout(%q) = (%+v, %v)", raw, got, err)
		}
	}
	withoutSession := httptest.NewRequest(http.MethodGet, "https://forum.example/front?iss="+url.QueryEscape(harness.issuer), nil)
	if got, err := client.ParseFrontChannelLogout(withoutSession); err != nil || got.SessionID != "" {
		t.Fatalf("optional front-channel sid = (%+v, %v)", got, err)
	}
}

func TestJARMRejectsInvalidClaims(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	provider := harness.discover(t)
	provider.enableJARM = true
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: harness.signingKey}, new(jose.SignerOptions).WithType("oauth-authz-resp+jwt").WithHeader(jose.HeaderKey("kid"), "exchange-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, claims := range []map[string]any{
		{"iss": "wrong", "aud": "gotth-bb", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "code": "c", "state": "s"},
		{"iss": harness.issuer, "aud": []string{"gotth-bb", "other"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "code": "c", "state": "s"},
		{"iss": harness.issuer, "aud": "gotth-bb", "iat": now.Unix(), "exp": now.Add(-time.Minute).Unix(), "code": "c", "state": "s"},
		{"iss": harness.issuer, "aud": "gotth-bb", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()},
		{"iss": harness.issuer, "aud": "gotth-bb", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "code": "c", "error": "denied", "state": "s"},
	} {
		raw, signErr := jwt.Signed(signer).Claims(claims).Serialize()
		if signErr != nil {
			t.Fatal(signErr)
		}
		if got, err := provider.verifyAuthorizationResponseJWT(context.Background(), raw, now); err == nil || got != (AuthorizationResponse{}) {
			t.Fatalf("JARM claims %+v = (%+v, %v), want zero/error", claims, got, err)
		}
	}
}

func TestEncryptedIDTokenAndJARMPaths(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	provider := harness.discover(t)
	tokens, err := provider.exchangeCode(context.Background(), "successful-code", harness.material.pkceVerifier, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &rsaKey.PublicKey}, new(jose.EncrypterOptions).WithContentType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(raw string) string {
		object, encryptErr := encrypter.Encrypt([]byte(raw))
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		compact, serializeErr := object.CompactSerialize()
		if serializeErr != nil {
			t.Fatal(serializeErr)
		}
		return compact
	}
	provider.tokenDecrypter = JOSEDecrypter{Key: rsaKey, KeyAlgorithms: []jose.KeyAlgorithm{jose.RSA_OAEP_256}, ContentEncryptions: []jose.ContentEncryption{jose.A256GCM}}
	if idToken, claims, err := provider.verifyIDToken(context.Background(), encrypt(tokens.IDToken)); err != nil || idToken.Subject != "subject-1" || claims == nil {
		t.Fatalf("encrypted ID token = (%+v, %v, %v)", idToken, claims, err)
	}
	provider.tokenDecrypter = nil
	if idToken, claims, err := provider.verifyIDToken(context.Background(), encrypt(tokens.IDToken)); err == nil || idToken != nil || claims != nil {
		t.Fatalf("encrypted token without decrypter = (%+v, %v, %v)", idToken, claims, err)
	}
	provider.tokenDecrypter = staticJWTDecrypter{err: errors.New("no key")}
	if _, _, err := provider.verifyIDToken(context.Background(), encrypt(tokens.IDToken)); err == nil {
		t.Fatal("decrypter failure was accepted")
	}

	provider = harness.discover(t)
	provider.enableJARM = true
	provider.tokenDecrypter = JOSEDecrypter{Key: rsaKey, KeyAlgorithms: []jose.KeyAlgorithm{jose.RSA_OAEP_256}, ContentEncryptions: []jose.ContentEncryption{jose.A256GCM}}
	jarmSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: harness.signingKey}, new(jose.SignerOptions).WithType("oauth-authz-resp+jwt").WithHeader(jose.HeaderKey("kid"), "exchange-test-key"))
	now := time.Now().UTC()
	raw, _ := jwt.Signed(jarmSigner).Claims(map[string]any{"iss": harness.issuer, "aud": "gotth-bb", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "code": "code", "state": "state"}).Serialize()
	if response, err := provider.verifyAuthorizationResponseJWT(context.Background(), encrypt(raw), now); err != nil || response.Code != "code" {
		t.Fatalf("encrypted JARM = (%+v, %v)", response, err)
	}
	rawError, _ := jwt.Signed(jarmSigner).Claims(map[string]any{"iss": harness.issuer, "aud": "gotth-bb", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "error": "access_denied", "state": "state"}).Serialize()
	if response, err := provider.verifyAuthorizationResponseJWT(context.Background(), rawError, now); err != nil || response.Error == nil || response.Error.Code != "access_denied" {
		t.Fatalf("JARM error = (%+v, %v)", response, err)
	}
}

func TestAuthorizationCapabilityFailures(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/cb", Transport: harness.server.Client().Transport, Entropy: bytes.NewReader(sequentialBytes(512)), AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []AuthorizationOptions{
		{OfflineAccess: true},
		{ACRValues: []string{"unsupported-acr"}},
		{UseRequestObject: true},
	} {
		if authorization, err := client.BeginContext(context.Background(), options); err == nil || authorization != (Authorization{}) {
			t.Fatalf("BeginContext(%+v) = (%+v, %v), want zero/error", options, authorization, err)
		}
	}
	client.provider.metadata.ResponseModes = []string{"query"}
	if authorization, err := client.BeginContext(context.Background(), AuthorizationOptions{ResponseMode: ResponseModeFormPost}); err == nil || authorization != (Authorization{}) {
		t.Fatalf("unsupported response mode = (%+v, %v)", authorization, err)
	}
	client.provider.metadata.ClaimsParameterSupported = false
	if authorization, err := client.BeginContext(context.Background(), AuthorizationOptions{Claims: json.RawMessage(`{"id_token":{}}`)}); err == nil || authorization != (Authorization{}) {
		t.Fatalf("unsupported claims parameter = (%+v, %v)", authorization, err)
	}
	if authorization, err := (*Client)(nil).BeginContext(context.Background(), AuthorizationOptions{}); err == nil || authorization != (Authorization{}) {
		t.Fatalf("nil client BeginContext = (%+v, %v)", authorization, err)
	}
}

func TestCompletionRejectsAttemptAndResponseMismatches(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/cb", Transport: harness.server.Client().Transport, Entropy: bytes.NewReader(sequentialBytes(640)), AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	begin := func() (Authorization, string) {
		authorization, beginErr := client.Begin()
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		parsed, _ := url.Parse(authorization.URL)
		return authorization, parsed.Query().Get("state")
	}
	authorization, state := begin()
	badEncoding := authorization.Attempt
	badEncoding.ContextCiphertext = "!"
	if _, err := client.Complete(context.Background(), state, "successful-code", badEncoding); err == nil {
		t.Fatal("invalid attempt context encoding accepted")
	}
	authorization, state = begin()
	if _, err := client.CompleteResponse(context.Background(), AuthorizationResponse{State: state, Code: "successful-code", Mode: ResponseModeFormPost}, authorization.Attempt); err == nil {
		t.Fatal("wrong response mode accepted")
	}
	authorization, state = begin()
	if _, err := client.CompleteResponse(context.Background(), AuthorizationResponse{State: state, Code: "successful-code", Issuer: "https://wrong.example", Mode: ResponseModeQuery}, authorization.Attempt); err == nil {
		t.Fatal("wrong response issuer accepted")
	}
	authorization, state = begin()
	authorizationError := &AuthorizationError{Code: "access_denied"}
	if _, err := client.CompleteResponse(context.Background(), AuthorizationResponse{State: state, Error: authorizationError, Mode: ResponseModeQuery}, authorization.Attempt); !errors.Is(err, authorizationError) {
		t.Fatalf("authorization error = %v, want original", err)
	}
}

func TestAttemptContextEnvelopeFailures(t *testing.T) {
	material, err := generateLoginMaterial(bytes.NewReader(sequentialBytes(96)))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(material.state))
	value := attemptContext{Version: attemptContextVersion, Issuer: "https://issuer.example", ClientID: "client", RedirectURL: "https://client.example/cb", ResponseMode: ResponseModeQuery, StartedAtUnix: time.Now().Unix()}
	envelope, err := sealAttemptContext(material.state, hash, value)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := openAttemptContext(material.state, hash, envelope); err != nil || opened.ClientID != "client" {
		t.Fatalf("openAttemptContext() = (%+v, %v)", opened, err)
	}
	for _, test := range []struct {
		state string
		hash  [sha256.Size]byte
		body  []byte
	}{
		{material.state, hash, nil},
		{material.state, hash, append([]byte{2}, envelope[1:]...)},
		{"bad", hash, envelope},
		{material.state, [sha256.Size]byte{}, envelope},
		{material.state, hash, append([]byte(nil), envelope[:len(envelope)-1]...)},
	} {
		if got, err := openAttemptContext(test.state, test.hash, test.body); err == nil || got.Version != 0 {
			t.Fatalf("openAttemptContext malformed = (%+v, %v)", got, err)
		}
	}
	if body, err := sealAttemptContext("bad", hash, value); err == nil || body != nil {
		t.Fatalf("sealAttemptContext bad state = (%x, %v)", body, err)
	}
}

func TestIDTokenBindingClaimFailures(t *testing.T) {
	provider := discoveredOIDCProvider{oauth2Config: oauth2.Config{ClientID: "client"}, trustedAudiences: []string{"api"}}
	now := time.Now().UTC()
	if err := provider.validateIDTokenBinding(nil, nil, attemptContext{}, now); err == nil {
		t.Fatal("nil ID token accepted")
	}
	for _, test := range []struct {
		token   *coreoidc.IDToken
		claims  map[string]json.RawMessage
		attempt attemptContext
	}{
		{&coreoidc.IDToken{Audience: []string{"client", "api"}}, map[string]json.RawMessage{}, attemptContext{}},
		{&coreoidc.IDToken{Audience: []string{"client"}}, map[string]json.RawMessage{"azp": json.RawMessage(`42`)}, attemptContext{}},
		{&coreoidc.IDToken{Audience: []string{"client"}}, map[string]json.RawMessage{}, attemptContext{MaxAgeSeconds: pointerInt64(60)}},
		{&coreoidc.IDToken{Audience: []string{"client"}}, map[string]json.RawMessage{"auth_time": json.RawMessage(fmt.Sprintf("%d", now.Add(-time.Hour).Unix()))}, attemptContext{MaxAgeSeconds: pointerInt64(60)}},
		{&coreoidc.IDToken{Audience: []string{"client"}}, map[string]json.RawMessage{}, attemptContext{ACRValues: []string{"urn:loa:2"}}},
		{&coreoidc.IDToken{Audience: []string{"client"}}, map[string]json.RawMessage{"acr": json.RawMessage(`"urn:loa:1"`)}, attemptContext{ACRValues: []string{"urn:loa:2"}}},
	} {
		if err := provider.validateIDTokenBinding(test.token, test.claims, test.attempt, now); err == nil {
			t.Fatalf("invalid ID-token binding accepted: %+v", test)
		}
	}
}

func pointerInt64(value int64) *int64 { return &value }

func TestUserInfoSignedAndFailureResponses(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	provider := harness.discover(t)
	tokens := tokenResponse{AccessToken: "access-token", TokenType: "Bearer"}
	harness.userInfoMode = "signed"
	claims, err := provider.fetchUserInfo(context.Background(), tokens, "subject-1", time.Now())
	if err != nil || string(claims["name"]) != `"UserInfo Name"` {
		t.Fatalf("signed UserInfo = (%v, %v)", claims, err)
	}
	for _, mode := range []string{"status", "oversize", "invalid-content", "invalid-json", "signed-wrong-issuer", "signed-wrong-audience", "signed-invalid-signature"} {
		harness.userInfoMode = mode
		if claims, err := provider.fetchUserInfo(context.Background(), tokens, "subject-1", time.Now()); err == nil || claims != nil {
			t.Fatalf("UserInfo mode %q = (%v, %v), want nil/error", mode, claims, err)
		}
	}
	harness.userInfoMode = ""
	harness.userInfoSubject = "other-subject"
	if claims, err := provider.fetchUserInfo(context.Background(), tokens, "subject-1", time.Now()); err == nil || claims != nil {
		t.Fatalf("wrong-subject UserInfo = (%v, %v), want nil/error", claims, err)
	}
	provider.metadata.UserInfoEndpoint = ""
	if claims, err := provider.fetchUserInfo(context.Background(), tokens, "subject-1", time.Now()); err == nil || claims != nil {
		t.Fatalf("missing-endpoint UserInfo = (%v, %v), want nil/error", claims, err)
	}
}

func TestAttemptContextRejectsWrongBindingAndBounds(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/cb", Transport: harness.server.Client().Transport, AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	base := attemptContext{Version: attemptContextVersion, Issuer: client.provider.issuer, ClientID: "gotth-bb", RedirectURL: "https://forum.example/cb", ResponseMode: ResponseModeQuery, StartedAtUnix: time.Now().Unix()}
	for _, mutate := range []func(*attemptContext){
		func(value *attemptContext) { value.Issuer = "https://wrong.example" },
		func(value *attemptContext) { value.ClientID = "wrong" },
		func(value *attemptContext) { value.RedirectURL = "https://wrong.example/cb" },
		func(value *attemptContext) { value.ResponseMode = "bad" },
		func(value *attemptContext) { invalid := int64(-1); value.MaxAgeSeconds = &invalid },
		func(value *attemptContext) { invalid := int64(366 * 24 * 60 * 60); value.MaxAgeSeconds = &invalid },
	} {
		value := base
		mutate(&value)
		if err := value.validateFor(client); err == nil {
			t.Fatalf("attempt context %+v was accepted", value)
		}
	}
	if err := base.validateFor(client); err != nil {
		t.Fatalf("valid attempt context rejected: %v", err)
	}
}

func TestTokenAndRevocationInputFailures(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Refresh(context.Background(), RefreshRequest{}); err == nil {
		t.Fatal("nil client refresh accepted")
	}
	if err := nilClient.Revoke(context.Background(), "token", ""); err == nil {
		t.Fatal("nil client revocation accepted")
	}
	if _, err := nilClient.DPoPProof(context.Background(), http.MethodGet, "https://api.example", "token", ""); err == nil {
		t.Fatal("nil client DPoP accepted")
	}
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret", RedirectURL: "https://forum.example/cb", Transport: harness.server.Client().Transport, AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []RefreshRequest{{RefreshToken: "refresh-token"}, {RefreshToken: "refresh-token", ExpectedSubject: strings.Repeat("s", 513)}, {RefreshToken: strings.Repeat("x", (64<<10)+1), ExpectedSubject: "subject"}} {
		if _, err := client.Refresh(context.Background(), request); err == nil {
			t.Fatalf("Refresh(%+v) accepted invalid input", request)
		}
	}
	if err := client.Revoke(context.Background(), "", ""); err == nil {
		t.Fatal("empty revocation token accepted")
	}
	if _, err := client.DPoPProof(context.Background(), http.MethodGet, "http://api.example", "token", ""); err == nil {
		t.Fatal("insecure DPoP target accepted")
	}
}

func TestAuthenticatedEndpointDPoPNonceRetryAndErrors(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	signer := JOSESigner{SignatureAlgorithm: jose.ES256, Key: harness.signingKey, EmbedPublicJWK: true}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		if current == 1 {
			writer.Header().Set("DPoP-Nonce", "server-nonce")
			writer.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(writer).Encode(map[string]string{"error": "use_dpop_nonce"})
			return
		}
		if request.Header.Get("DPoP") == "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]string{"value": "ok"})
	}))
	defer server.Close()
	provider := discoveredOIDCProvider{httpClient: server.Client(), oauth2Config: oauth2.Config{ClientID: "client"}, clientAuth: ClientAuthentication{Method: ClientAuthNone}, dpopSigner: signer}
	var result struct{ Value string }
	if err := provider.doAuthenticatedJSON(context.Background(), server.URL, url.Values{"x": {"y"}}, time.Now(), &result); err != nil || result.Value != "ok" || calls.Load() != 2 {
		t.Fatalf("DPoP nonce retry = (%+v, calls=%d, err=%v)", result, calls.Load(), err)
	}

	for _, mode := range []string{"content", "error", "status", "invalid-json", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			failure := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch mode {
				case "content":
					writer.Header().Set("Content-Type", "text/plain")
					_, _ = writer.Write([]byte(`{}`))
				case "error":
					writer.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(writer).Encode(map[string]string{"error": "invalid_request"})
				case "status":
					writer.WriteHeader(http.StatusBadGateway)
					_, _ = writer.Write([]byte(`{}`))
				case "invalid-json":
					_, _ = writer.Write([]byte("{"))
				case "oversize":
					_, _ = writer.Write([]byte(strings.Repeat(" ", maxDirectResponseBytes+1)))
				}
			}))
			defer failure.Close()
			provider.httpClient = failure.Client()
			if err := provider.doAuthenticatedJSON(context.Background(), failure.URL, nil, time.Now(), &map[string]any{}); err == nil {
				t.Fatalf("endpoint mode %q unexpectedly succeeded", mode)
			}
		})
	}
}

func TestPARRejectsMissingAndMalformedResponses(t *testing.T) {
	provider := discoveredOIDCProvider{}
	if uri, err := provider.pushAuthorizationRequest(context.Background(), nil, time.Now()); err == nil || uri != "" {
		t.Fatalf("missing PAR endpoint = (%q, %v)", uri, err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"request_uri": "relative", "expires_in": 60})
	}))
	defer server.Close()
	provider.metadata.PAREndpoint = server.URL
	provider.httpClient = server.Client()
	provider.oauth2Config.ClientID = "client"
	provider.clientAuth.Method = ClientAuthNone
	if uri, err := provider.pushAuthorizationRequest(context.Background(), nil, time.Now()); err == nil || uri != "" {
		t.Fatalf("malformed PAR response = (%q, %v)", uri, err)
	}
}

func TestAuthenticatedRequestMethods(t *testing.T) {
	base := discoveredOIDCProvider{oauth2Config: oauth2.Config{ClientID: "client"}, clientSecret: "secret"}
	for _, method := range []ClientAuthenticationMethod{ClientAuthNone, ClientSecretBasic, ClientSecretPost, TLSClientAuth, SelfSignedTLSClientAuth} {
		provider := base
		provider.clientAuth.Method = method
		request, err := provider.newAuthenticatedFormRequest(context.Background(), "https://issuer.example/token", url.Values{"grant_type": {"authorization_code"}}, time.Now(), "")
		if err != nil {
			t.Fatalf("newAuthenticatedFormRequest(%s): %v", method, err)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch method {
		case ClientSecretBasic:
			if username, password, ok := request.BasicAuth(); !ok || username != "client" || password != "secret" {
				t.Fatalf("basic credentials = (%q, %q, %v)", username, password, ok)
			}
		case ClientSecretPost:
			if request.Form.Get("client_id") != "client" || request.Form.Get("client_secret") != "secret" {
				t.Fatalf("post credentials = %v", request.Form)
			}
		default:
			if request.Form.Get("client_id") != "client" || request.Form.Get("client_secret") != "" {
				t.Fatalf("public/TLS credentials = %v", request.Form)
			}
		}
	}
	provider := base
	provider.clientAuth = ClientAuthentication{Method: PrivateKeyJWT, Signer: failingJWTSigner{algorithm: "ES256"}}
	if _, err := provider.newAuthenticatedFormRequest(context.Background(), "https://issuer.example/token", nil, time.Now(), ""); err == nil {
		t.Fatal("failing client assertion signer was accepted")
	}
	provider.clientAuth.Method = "bad"
	if _, err := provider.newAuthenticatedFormRequest(context.Background(), "https://issuer.example/token", nil, time.Now(), ""); err == nil {
		t.Fatal("unknown client authentication method was accepted")
	}
}

func TestRegistrationRejectsInvalidInputsAndResponses(t *testing.T) {
	if got, err := RegisterClient(nil, RegistrationConfig{}); err == nil || got.ClientID != "" {
		t.Fatalf("RegisterClient(nil) = (%+v, %v)", got, err)
	}
	for _, mode := range []string{"status", "content-type", "invalid-json", "missing-id", "bad-management"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch mode {
				case "status":
					writer.WriteHeader(http.StatusBadRequest)
					return
				case "content-type":
					writer.Header().Set("Content-Type", "text/plain")
				case "invalid-json":
					writer.WriteHeader(http.StatusCreated)
					_, _ = writer.Write([]byte("{"))
					return
				}
				writer.WriteHeader(http.StatusCreated)
				response := map[string]any{"client_id": "client"}
				if mode == "missing-id" {
					delete(response, "client_id")
				}
				if mode == "bad-management" {
					response["registration_client_uri"] = "http://example.com/manage"
				}
				_ = json.NewEncoder(writer).Encode(response)
			}))
			defer server.Close()
			got, err := RegisterClient(context.Background(), RegistrationConfig{Endpoint: server.URL, Metadata: json.RawMessage(`{"redirect_uris":["https://client.example/cb"]}`), Transport: server.Client().Transport})
			if err == nil || got.ClientID != "" {
				t.Fatalf("RegisterClient(%s) = (%+v, %v), want zero/error", mode, got, err)
			}
		})
	}
}

func TestRegistrationManagementRejectsFailures(t *testing.T) {
	registration := ClientRegistration{RegistrationAccessToken: "token"}
	if _, err := manageClientRegistration(nil, http.MethodGet, registration, nil, nil); err == nil {
		t.Fatal("nil registration context accepted")
	}
	for _, mode := range []string{"status", "content", "invalid", "delete-status"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if mode == "delete-status" && request.Method == http.MethodDelete {
					writer.WriteHeader(http.StatusOK)
					return
				}
				if mode == "status" {
					writer.WriteHeader(http.StatusBadGateway)
					return
				}
				if mode == "content" {
					writer.Header().Set("Content-Type", "text/plain")
				}
				if mode == "invalid" {
					_, _ = writer.Write([]byte("{"))
					return
				}
				_, _ = writer.Write([]byte(`{}`))
			}))
			defer server.Close()
			registration.RegistrationClientURI = server.URL
			if mode == "delete-status" {
				if err := DeleteClientRegistration(context.Background(), registration, server.Client().Transport); err == nil {
					t.Fatal("bad deletion status accepted")
				}
				return
			}
			if result, err := ReadClientRegistration(context.Background(), registration, server.Client().Transport); err == nil || result != nil {
				t.Fatalf("management mode %q = (%s, %v)", mode, result, err)
			}
		})
	}
}
