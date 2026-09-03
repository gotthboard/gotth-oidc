package oidc

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	oidcHTTPTimeout          = 10 * time.Second
	oidcHTTPResponseMaxBytes = 512 << 10
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type providerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURL                           string   `json:"jwks_uri"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	PAREndpoint                       string   `json:"pushed_authorization_request_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	CheckSessionIframe                string   `json:"check_session_iframe"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	Algorithms                        []string `json:"id_token_signing_alg_values_supported"`
	JARMAlgorithms                    []string `json:"authorization_signing_alg_values_supported"`
	RequestObjectSigningAlgorithms    []string `json:"request_object_signing_alg_values_supported"`
	ResponseTypes                     []string `json:"response_types_supported"`
	ResponseModes                     []string `json:"response_modes_supported"`
	GrantTypes                        []string `json:"grant_types_supported"`
	SubjectTypes                      []string `json:"subject_types_supported"`
	Scopes                            []string `json:"scopes_supported"`
	Claims                            []string `json:"claims_supported"`
	ACRValues                         []string `json:"acr_values_supported"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
	UserInfoSigningAlgorithms         []string `json:"userinfo_signing_alg_values_supported"`
	IDTokenEncryptionAlgorithms       []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionMethods          []string `json:"id_token_encryption_enc_values_supported"`
	TokenAuthMethods                  []string `json:"token_endpoint_auth_methods_supported"`
	TokenAuthSigningAlgs              []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	PKCEMethods                       []string `json:"code_challenge_methods_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameter               bool     `json:"request_uri_parameter_supported"`
	RequirePAR                        bool     `json:"require_pushed_authorization_requests"`
	ResponseIssuerSupported           bool     `json:"authorization_response_iss_parameter_supported"`
	FrontChannelLogoutSupported       bool     `json:"frontchannel_logout_supported"`
	FrontChannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required"`
	BackChannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
	BackChannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required"`
	DPoPAlgorithms                    []string `json:"dpop_signing_alg_values_supported"`
	MTLSEndpointAliases               struct {
		TokenEndpoint      string `json:"token_endpoint"`
		RevocationEndpoint string `json:"revocation_endpoint"`
		UserInfoEndpoint   string `json:"userinfo_endpoint"`
		PAREndpoint        string `json:"pushed_authorization_request_endpoint"`
	} `json:"mtls_endpoint_aliases"`
}

type discoveredOIDCProvider struct {
	issuer              string
	provider            *coreoidc.Provider
	verifier            *coreoidc.IDTokenVerifier
	keySet              coreoidc.KeySet
	httpClient          *http.Client
	oauth2Config        oauth2.Config
	metadata            providerMetadata
	clientAuth          ClientAuthentication
	clientSecret        string
	trustedAudiences    []string
	requestObjectSigner JWTSigner
	tokenDecrypter      JWTDecrypter
	enableJARM          bool
	enablePAR           bool
	enableMutualTLS     bool
	dpopSigner          JWTSigner
}

func isHTTPSOrNumericLoopbackHTTP(parsed url.URL) bool {
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(parsed.Hostname())
	return ip != nil && ip.IsLoopback()
}

func (provider discoveredOIDCProvider) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED OIDC PROVIDER]")
}

func discoverOIDCProvider(ctx context.Context, baseTransport http.RoundTripper, issuerURL url.URL, clientID, clientSecret, redirectURL string) (discoveredOIDCProvider, error) {
	return discoverOIDCProviderWithConfig(ctx, baseTransport, issuerURL, Config{
		IssuerURL: issuerURL.String(), ClientID: clientID, ClientSecret: clientSecret,
		RedirectURL: redirectURL, AllowInsecureLoopback: true,
	})
}

func discoverOIDCProviderWithConfig(ctx context.Context, baseTransport http.RoundTripper, issuerURL url.URL, config Config) (discoveredOIDCProvider, error) {
	if ctx == nil {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC discovery context is required")
	}
	if err := ctx.Err(); err != nil {
		return discoveredOIDCProvider{}, fmt.Errorf("discover OIDC provider: %w", err)
	}
	if config.ClientID == "" {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC client ID is required")
	}
	issuer, err := validateNetworkURL("OIDC issuer", issuerURL.String(), config.AllowInsecureLoopback, false, false)
	if err != nil {
		return discoveredOIDCProvider{}, err
	}
	redirect, err := validateNetworkURL("OIDC callback", config.RedirectURL, config.AllowInsecureLoopback, true, false)
	if err != nil {
		return discoveredOIDCProvider{}, err
	}
	policy := config.EndpointPolicy
	if policy == nil {
		policy = SameOriginEndpoints
	}
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	discoveryClient := boundedOIDCHTTPClient(baseTransport, map[string]bool{issuer.Scheme + "://" + issuer.Host: true})
	discoveryTransport := discoveryClient.Transport
	discoveryClient.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		response, err := discoveryTransport.RoundTrip(request)
		if err != nil {
			return nil, err
		}
		mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if mediaType != "application/json" {
			_ = response.Body.Close()
			return nil, fmt.Errorf("OIDC discovery response has an invalid content type")
		}
		return response, nil
	})
	providerContext := coreoidc.ClientContext(ctx, discoveryClient)
	provider, err := coreoidc.NewProvider(providerContext, issuer.String())
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return discoveredOIDCProvider{}, fmt.Errorf("discover OIDC provider: %w", contextError)
		}
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider discovery failed")
	}
	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider metadata decoding failed")
	}
	if metadata.Issuer != issuer.String() {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC discovery issuer does not match configuration")
	}
	if !slices.Contains(metadata.ResponseTypes, "code") {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not support the authorization code response type")
	}
	if len(metadata.SubjectTypes) == 0 {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider omits required subject types")
	}
	for _, subjectType := range metadata.SubjectTypes {
		if subjectType != "public" && subjectType != "pairwise" {
			return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider advertises an invalid subject type")
		}
	}
	if len(metadata.GrantTypes) != 0 && !slices.Contains(metadata.GrantTypes, "authorization_code") {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not support the authorization_code grant")
	}
	if len(metadata.Scopes) != 0 && !slices.Contains(metadata.Scopes, "openid") {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise the openid scope")
	}
	if len(metadata.PKCEMethods) != 0 && !slices.Contains(metadata.PKCEMethods, "S256") {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise S256 PKCE")
	}
	supportedAlgorithms := safeSigningAlgorithms(metadata.Algorithms)
	if len(supportedAlgorithms) == 0 {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider advertises no supported ID-token signing algorithm")
	}
	if !slices.Contains(metadata.Algorithms, coreoidc.RS256) {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider omits mandatory RS256 support")
	}
	endpointSpecs := []struct {
		kind     EndpointKind
		name     string
		raw      string
		required bool
	}{
		{EndpointAuthorization, "OIDC authorization endpoint", metadata.AuthorizationEndpoint, true},
		{EndpointToken, "OIDC token endpoint", metadata.TokenEndpoint, true},
		{EndpointJWKS, "OIDC JWKS endpoint", metadata.JWKSURL, true},
		{EndpointUserInfo, "OIDC UserInfo endpoint", metadata.UserInfoEndpoint, false},
		{EndpointPAR, "OIDC PAR endpoint", metadata.PAREndpoint, false},
		{EndpointRegistration, "OIDC registration endpoint", metadata.RegistrationEndpoint, false},
		{EndpointLogout, "OIDC end-session endpoint", metadata.EndSessionEndpoint, false},
		{EndpointSession, "OIDC check-session iframe", metadata.CheckSessionIframe, false},
		{EndpointRevocation, "OIDC revocation endpoint", metadata.RevocationEndpoint, false},
	}
	allowedOrigins := map[string]bool{issuer.Scheme + "://" + issuer.Host: true}
	for _, spec := range endpointSpecs {
		if spec.raw == "" && !spec.required {
			continue
		}
		endpoint, endpointErr := validateNetworkURL(spec.name, spec.raw, config.AllowInsecureLoopback, true, true)
		if endpointErr != nil {
			return discoveredOIDCProvider{}, endpointErr
		}
		if endpointErr := policy.AllowEndpoint(spec.kind, issuer, endpoint); endpointErr != nil {
			return discoveredOIDCProvider{}, fmt.Errorf("%s is rejected by policy: %w", spec.name, endpointErr)
		}
		allowedOrigins[endpoint.Scheme+"://"+endpoint.Host] = true
	}
	clientAuth, err := validateClientAuthentication(config, metadata)
	if err != nil {
		return discoveredOIDCProvider{}, err
	}
	if config.RequireAuthorizationResponseIssuer && !metadata.ResponseIssuerSupported {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not support authorization response issuer identification")
	}
	if config.EnablePAR && metadata.PAREndpoint == "" {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise PAR")
	}
	if config.EnableJARM && len(safeSigningAlgorithms(metadata.JARMAlgorithms)) == 0 {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise a supported JARM signing algorithm")
	}
	if config.TokenDecrypter != nil && (len(metadata.IDTokenEncryptionAlgorithms) == 0 || len(metadata.IDTokenEncryptionMethods) == 0) {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise encrypted ID-token algorithms")
	}
	if config.RequestObjectSigner != nil && !metadata.RequestParameterSupported && !config.EnablePAR {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise request objects")
	}
	if config.RequestObjectSigner != nil && len(metadata.RequestObjectSigningAlgorithms) != 0 && !slices.Contains(metadata.RequestObjectSigningAlgorithms, config.RequestObjectSigner.Algorithm()) {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise the request-object signing algorithm")
	}
	if config.DPoPSigner != nil && (!slices.Contains(metadata.DPoPAlgorithms, config.DPoPSigner.Algorithm()) || !containsString(safeProofAlgorithms(), config.DPoPSigner.Algorithm())) {
		return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise a safe DPoP signing algorithm")
	}
	if config.DPoPSigner != nil {
		if _, ok := config.DPoPSigner.(DPoPKeyThumbprinter); !ok {
			return discoveredOIDCProvider{}, fmt.Errorf("OIDC DPoP signer does not expose a public-key thumbprint")
		}
	}
	if config.EnableMutualTLS {
		if metadata.MTLSEndpointAliases.TokenEndpoint == "" {
			return discoveredOIDCProvider{}, fmt.Errorf("OIDC provider does not advertise mutual-TLS token endpoint aliases")
		}
		aliases := []struct {
			kind EndpointKind
			name string
			raw  string
		}{{EndpointToken, "token", metadata.MTLSEndpointAliases.TokenEndpoint}, {EndpointRevocation, "revocation", metadata.MTLSEndpointAliases.RevocationEndpoint}, {EndpointUserInfo, "UserInfo", metadata.MTLSEndpointAliases.UserInfoEndpoint}, {EndpointPAR, "PAR", metadata.MTLSEndpointAliases.PAREndpoint}}
		for _, alias := range aliases {
			if alias.raw == "" {
				continue
			}
			parsedAlias, endpointErr := validateNetworkURL("OIDC mutual-TLS "+alias.name+" endpoint", alias.raw, config.AllowInsecureLoopback, true, true)
			if endpointErr != nil {
				return discoveredOIDCProvider{}, endpointErr
			}
			if endpointErr := policy.AllowEndpoint(alias.kind, issuer, parsedAlias); endpointErr != nil {
				return discoveredOIDCProvider{}, fmt.Errorf("OIDC mutual-TLS %s endpoint is rejected by policy: %w", alias.name, endpointErr)
			}
			allowedOrigins[parsedAlias.Scheme+"://"+parsedAlias.Host] = true
		}
		metadata.TokenEndpoint = metadata.MTLSEndpointAliases.TokenEndpoint
	}
	httpClient := boundedOIDCHTTPClient(baseTransport, allowedOrigins)
	endpoint := oauth2.Endpoint{AuthURL: metadata.AuthorizationEndpoint, TokenURL: metadata.TokenEndpoint}
	switch clientAuth.Method {
	case ClientSecretBasic:
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case ClientSecretPost, ClientAuthNone:
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	default:
		endpoint.AuthStyle = oauth2.AuthStyleAutoDetect
	}
	oauthConfig := oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, Endpoint: endpoint, RedirectURL: redirect.String(), Scopes: []string{"openid", "profile", "email"}}
	keySet := coreoidc.NewRemoteKeySet(coreoidc.ClientContext(context.Background(), httpClient), metadata.JWKSURL)
	verifier := coreoidc.NewVerifier(issuer.String(), keySet, &coreoidc.Config{ClientID: config.ClientID, SupportedSigningAlgs: supportedAlgorithms})
	return discoveredOIDCProvider{
		issuer: issuer.String(), provider: provider, verifier: verifier, keySet: keySet, httpClient: httpClient,
		oauth2Config: oauthConfig, metadata: metadata, clientAuth: clientAuth,
		clientSecret: config.ClientSecret, trustedAudiences: append([]string(nil), config.TrustedAudiences...),
		requestObjectSigner: config.RequestObjectSigner, tokenDecrypter: config.TokenDecrypter,
		enableJARM: config.EnableJARM, enablePAR: config.EnablePAR,
		enableMutualTLS: config.EnableMutualTLS, dpopSigner: config.DPoPSigner,
	}, nil
}

func validateNetworkURL(name, raw string, allowLoopback, allowQuery, endpoint bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("%s is not an absolute hierarchical URL", name)
	}
	if parsed.Scheme != "https" && !(allowLoopback && isHTTPSOrNumericLoopbackHTTP(*parsed)) {
		return nil, fmt.Errorf("%s must use HTTPS%s", name, map[bool]string{true: " or explicitly enabled numeric-loopback HTTP"}[allowLoopback])
	}
	if parsed.User != nil || (!allowQuery && (parsed.RawQuery != "" || parsed.ForceQuery)) || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s contains forbidden URI components", name)
	}
	if endpoint && parsed.Path == "" {
		parsed.Path = "/"
		if parsed.String() != raw+"/" && parsed.String() != raw {
			return nil, fmt.Errorf("%s is not canonically encoded", name)
		}
	} else if parsed.String() != raw {
		return nil, fmt.Errorf("%s is not canonically encoded", name)
	}
	return parsed, nil
}

func boundedOIDCHTTPClient(base http.RoundTripper, allowedOrigins map[string]bool) *http.Client {
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request == nil || request.URL == nil || !allowedOrigins[request.URL.Scheme+"://"+request.URL.Host] {
			return nil, fmt.Errorf("OIDC request escaped the validated endpoint origins")
		}
		response, err := base.RoundTrip(request)
		if err != nil {
			return nil, err
		}
		if response == nil || response.Body == nil {
			return nil, fmt.Errorf("OIDC transport returned an invalid response")
		}
		response.Body = http.MaxBytesReader(nil, response.Body, oidcHTTPResponseMaxBytes)
		return response, nil
	})
	return &http.Client{Transport: transport, Timeout: oidcHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("OIDC redirects are not allowed") }}
}

func safeSigningAlgorithms(advertised []string) []string {
	result := make([]string, 0, len(advertised))
	for _, algorithm := range advertised {
		switch algorithm {
		case coreoidc.RS256, coreoidc.RS384, coreoidc.RS512, coreoidc.ES256, coreoidc.ES384, coreoidc.ES512,
			coreoidc.PS256, coreoidc.PS384, coreoidc.PS512, coreoidc.EdDSA:
			if !slices.Contains(result, algorithm) {
				result = append(result, algorithm)
			}
		}
	}
	slices.Sort(result)
	return result
}

func validateClientAuthentication(config Config, metadata providerMetadata) (ClientAuthentication, error) {
	auth := config.ClientAuthentication
	if auth.Method == "" {
		if config.ClientSecret == "" {
			auth.Method = ClientAuthNone
		} else {
			auth.Method = ClientSecretBasic
		}
	}
	methods := append([]string(nil), metadata.TokenAuthMethods...)
	if len(methods) == 0 {
		methods = []string{string(ClientSecretBasic)}
	}
	if !slices.Contains(methods, string(auth.Method)) {
		return ClientAuthentication{}, fmt.Errorf("OIDC provider does not advertise client authentication method %s", auth.Method)
	}
	switch auth.Method {
	case ClientAuthNone:
		if config.ClientSecret != "" {
			return ClientAuthentication{}, fmt.Errorf("OIDC public client authentication cannot retain a client secret")
		}
	case ClientSecretBasic, ClientSecretPost:
		if config.ClientSecret == "" {
			return ClientAuthentication{}, fmt.Errorf("OIDC client-secret authentication requires a client secret")
		}
	case ClientSecretJWT:
		if config.ClientSecret == "" {
			return ClientAuthentication{}, fmt.Errorf("OIDC client_secret_jwt requires a client secret")
		}
		if auth.Signer == nil {
			algorithm := ""
			for _, candidate := range []string{"HS256", "HS384", "HS512"} {
				if slices.Contains(metadata.TokenAuthSigningAlgs, candidate) {
					algorithm = candidate
					break
				}
			}
			minimum := map[string]int{"HS256": 32, "HS384": 48, "HS512": 64}[algorithm]
			if algorithm == "" || len(config.ClientSecret) < minimum {
				return ClientAuthentication{}, fmt.Errorf("OIDC client_secret_jwt has no safe advertised algorithm or sufficient secret entropy")
			}
			auth.Signer = JOSESigner{SignatureAlgorithm: jose.SignatureAlgorithm(algorithm), Key: []byte(config.ClientSecret)}
		}
		fallthrough
	case PrivateKeyJWT:
		if auth.Signer == nil {
			return ClientAuthentication{}, fmt.Errorf("OIDC JWT client authentication requires a signer")
		}
		if len(metadata.TokenAuthSigningAlgs) != 0 && !slices.Contains(metadata.TokenAuthSigningAlgs, auth.Signer.Algorithm()) {
			return ClientAuthentication{}, fmt.Errorf("OIDC provider does not advertise the client assertion signing algorithm")
		}
	case TLSClientAuth, SelfSignedTLSClientAuth:
		if !config.EnableMutualTLS {
			return ClientAuthentication{}, fmt.Errorf("OIDC TLS client authentication requires mutual-TLS endpoint aliases")
		}
	default:
		return ClientAuthentication{}, fmt.Errorf("OIDC client authentication method is unsupported")
	}
	return auth, nil
}

func endpointSupports(metadataValues []string, value string, defaults ...string) bool {
	if len(metadataValues) == 0 {
		metadataValues = defaults
	}
	return slices.Contains(metadataValues, value)
}
