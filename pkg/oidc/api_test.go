package oidc

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

const validEncodedLoginState = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestClientRejectsIncompleteUseAndRedactsFormatting(t *testing.T) {
	var client *Client
	if _, err := client.Begin(); err == nil {
		t.Fatal("nil Client.Begin() returned no error")
	}
	if _, err := client.Complete(context.Background(), "state", "code", ProtectedAttempt{}); err == nil {
		t.Fatal("nil Client.Complete() returned no error")
	}
	formatted := fmt.Sprintf("%+v", Client{})
	if formatted != "[REDACTED OIDC CLIENT]" || strings.Contains(formatted, "secret") {
		t.Fatalf("formatted client = %q", formatted)
	}
}

func TestCloneStringDoesNotAlias(t *testing.T) {
	if cloneString(nil) != nil {
		t.Fatal("cloneString(nil) returned a value")
	}
	value := "member@example.com"
	got := cloneString(&value)
	if got == nil || *got != value || got == &value {
		t.Fatalf("cloneString() = %#v", got)
	}
}

func TestPublicAPIReturnsEveryFailureBoundary(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()

	defaultEntropy, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret",
		RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport,
		AllowInsecureLoopback: true,
	})
	if err != nil || defaultEntropy.entropy == nil {
		t.Fatalf("New() default entropy = (%+v, %v)", defaultEntropy, err)
	}
	for name, client := range map[string]*Client{
		"generation":    {entropy: errReader{cause: fmt.Errorf("generation failed")}},
		"protection":    {entropy: bytes.NewReader(sequentialBytes(96))},
		"authorization": {entropy: bytes.NewReader(sequentialBytes(120))},
	} {
		if authorization, beginErr := client.Begin(); beginErr == nil || authorization != (Authorization{}) {
			t.Errorf("%s Begin() = (%+v, %v), want zero/error", name, authorization, beginErr)
		}
	}

	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret",
		RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport,
		Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	authorization, err := client.Begin()
	if err != nil {
		t.Fatalf("Begin() returned error: %v", err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatalf("url.Parse() returned error: %v", err)
	}
	if identity, completeErr := client.Complete(context.Background(), parsed.Query().Get("state"), "exchange-failure", authorization.Attempt); completeErr == nil || identity != (Identity{}) {
		t.Fatalf("Complete() = (%+v, %v), want zero/error", identity, completeErr)
	}
}

func TestConfidentialClientCompletesOneHardenedFlow(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb", ClientSecret: "client-secret",
		RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport,
		Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	authorization, err := client.Begin()
	if err != nil {
		t.Fatalf("Begin() returned error: %v", err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatalf("url.Parse() returned error: %v", err)
	}
	state := parsed.Query().Get("state")
	if state != harness.material.state || parsed.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization query = %v", parsed.Query())
	}
	identity, err := client.Complete(context.Background(), state, "successful-code", authorization.Attempt)
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}
	if identity.Issuer != harness.issuer || identity.Subject != "subject-1" || identity.DisplayName != "Danny Hunn" ||
		identity.Email == nil || *identity.Email != "danny@example.com" || identity.PictureURL == nil {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestPublicClientCompletesOneHardenedFlow(t *testing.T) {
	harness := newOIDCExchangeHarness(t)
	defer harness.server.Close()
	harness.publicClient = true
	client, err := New(context.Background(), Config{
		IssuerURL: harness.issuer, ClientID: "gotth-bb",
		RedirectURL: "https://forum.example/bb/auth/callback", Transport: harness.server.Client().Transport,
		Entropy: bytes.NewReader(sequentialBytes(120)), AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	authorization, err := client.Begin()
	if err != nil {
		t.Fatalf("Begin() returned error: %v", err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatalf("url.Parse() returned error: %v", err)
	}
	state := parsed.Query().Get("state")
	identity, err := client.Complete(context.Background(), state, "successful-code", authorization.Attempt)
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}
	if identity.Subject != "subject-1" || harness.tokenRequestCount("successful-code") != 1 {
		t.Fatalf("public-client result = (%+v, requests=%d)", identity, harness.tokenRequestCount("successful-code"))
	}
}

func TestPublicClientRejectsInvalidConfigurationAndAttempt(t *testing.T) {
	if client, err := New(context.Background(), Config{IssuerURL: "://"}); err == nil || client != nil {
		t.Fatalf("New() = (%+v, %v)", client, err)
	}
	client := &Client{}
	if _, err := client.Begin(); err == nil {
		t.Fatal("uninitialized Begin() returned no error")
	}
	if _, err := client.Complete(context.Background(), "bad", "code", ProtectedAttempt{}); err == nil {
		t.Fatal("invalid Complete() returned no error")
	}
}

func sequentialBytes(length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = byte(index)
	}
	return result
}
