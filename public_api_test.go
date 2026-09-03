package oidc_test

import (
	"context"
	"fmt"
	"testing"

	gotthoidc "git.dannyhunn.com/agents/gotth-oidc"
)

func TestPublicAPIIsUsableOutsidePackage(t *testing.T) {
	var _ fmt.Formatter = (*gotthoidc.Client)(nil)
	var _ = gotthoidc.ProtectedAttempt{}
	var _ = gotthoidc.Authorization{}
	var _ = gotthoidc.Identity{}
	client, err := gotthoidc.New(context.Background(), gotthoidc.Config{
		IssuerURL: "http://auth.example/issuer/", ClientID: "consumer",
		RedirectURL: "https://consumer.example/callback",
	})
	if err == nil || client != nil {
		t.Fatalf("New() = (%v, %v), want nil/error for insecure issuer", client, err)
	}
}
