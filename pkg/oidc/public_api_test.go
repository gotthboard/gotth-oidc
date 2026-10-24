package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
)

func TestPublicAPIIsUsableOutsidePackage(t *testing.T) {
	var _ fmt.Formatter = (*gotthoidc.Client)(nil)
	var _ = gotthoidc.ProtectedAttempt{}
	var _ = gotthoidc.Authorization{}
	var _ = gotthoidc.Identity{}
	var _ gotthoidc.EndpointPolicy = gotthoidc.SameOriginEndpoints
	var _ gotthoidc.JWTSigner = gotthoidc.JOSESigner{}
	var _ gotthoidc.DPoPKeyThumbprinter = gotthoidc.JOSESigner{}
	var _ gotthoidc.JWTDecrypter = gotthoidc.JOSEDecrypter{}
	var _ = gotthoidc.AuthorizationOptions{ResponseMode: gotthoidc.ResponseModeFormPost, MaxAge: pointerDuration(time.Minute), UseUserInfo: true, UsePAR: true, UseRequestObject: true}
	var _ = gotthoidc.AuthorizationResponse{}
	var _ = gotthoidc.ClientAuthentication{Method: gotthoidc.PrivateKeyJWT}
	var _ = gotthoidc.IdentityPolicy{RequireVerifiedEmail: true}
	var _ = gotthoidc.TokenSet{}
	var _ = gotthoidc.Completion{}
	var _ = gotthoidc.RefreshRequest{}
	var _ = gotthoidc.LogoutRequest{}
	var _ = gotthoidc.LogoutToken{}
	var _ = gotthoidc.FrontChannelLogout{}
	var _ = gotthoidc.IssuerDiscoveryConfig{}
	var _ = gotthoidc.RegistrationConfig{Metadata: json.RawMessage(`{}`)}
	var _ = gotthoidc.ClientRegistration{}
	var _ = gotthoidc.ParseCallback
	var _ = gotthoidc.DiscoverIssuer
	var _ = gotthoidc.RegisterClient
	var _ = gotthoidc.ReadClientRegistration
	var _ = gotthoidc.UpdateClientRegistration
	var _ = gotthoidc.DeleteClientRegistration
	client, err := gotthoidc.New(context.Background(), gotthoidc.Config{
		IssuerURL: "http://auth.example/issuer/", ClientID: "consumer",
		RedirectURL: "https://consumer.example/callback",
	})
	if err == nil || client != nil {
		t.Fatalf("New() = (%v, %v), want nil/error for insecure issuer", client, err)
	}
}

func TestAuthorizationErrorIsInspectable(t *testing.T) {
	original := &gotthoidc.AuthorizationError{Code: "access_denied", Description: "request denied", URI: "https://issuer.example/errors/access_denied"}
	var err error = original
	var target *gotthoidc.AuthorizationError
	if !errors.As(err, &target) {
		t.Fatal("errors.As did not expose AuthorizationError")
	}
	if target != original || target.Code != original.Code || target.Description != original.Description || target.URI != original.URI {
		t.Fatalf("inspected authorization error = %+v, want %+v", target, original)
	}
}

func pointerDuration(value time.Duration) *time.Duration { return &value }
