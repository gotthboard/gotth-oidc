package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type protectedAttemptFixture struct {
	Schema        int              `json:"schema"`
	SourceVersion string           `json:"source_version"`
	SourceCommit  string           `json:"source_commit"`
	State         string           `json:"state"`
	Attempt       ProtectedAttempt `json:"attempt"`
	Expected      struct {
		Nonce        string         `json:"nonce"`
		PKCEVerifier string         `json:"pkce_verifier"`
		Context      attemptContext `json:"context"`
	} `json:"expected"`
}

func TestV1ReadsV010ProtectedAttemptGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/protected-attempt-v0.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture protectedAttemptFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != 1 || fixture.SourceVersion != "v0.1.0" || fixture.SourceCommit != "4c22b248b2e7f03c28051aaf3105a0d769690f73" {
		t.Fatalf("unexpected fixture identity: %+v", fixture)
	}
	material, err := recoverLoginMaterial(
		fixture.State,
		fixture.Attempt.StateHash[:],
		fixture.Attempt.NonceCiphertext[:],
		fixture.Attempt.PKCEVerifierCiphertext[:],
	)
	if err != nil {
		t.Fatalf("recover v0.1.0 login envelopes: %v", err)
	}
	if material.nonce != fixture.Expected.Nonce || material.pkceVerifier != fixture.Expected.PKCEVerifier {
		t.Fatal("recovered v0.1.0 material does not match golden values")
	}
	contextEnvelope, err := base64.RawURLEncoding.Strict().DecodeString(fixture.Attempt.ContextCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	contextValue, err := openAttemptContext(fixture.State, fixture.Attempt.StateHash, contextEnvelope)
	if err != nil {
		t.Fatalf("open v0.1.0 context envelope: %v", err)
	}
	if !reflect.DeepEqual(contextValue, fixture.Expected.Context) {
		t.Fatalf("context = %+v, want %+v", contextValue, fixture.Expected.Context)
	}

	roundTrip, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip = append(roundTrip, '\n')
	if !bytes.Equal(roundTrip, raw) {
		t.Fatal("ProtectedAttempt JSON persistence representation drifted from the v0.1.0 golden fixture")
	}
}

func TestProtectedAttemptEnvelopeVersionPolicy(t *testing.T) {
	raw, err := os.ReadFile("testdata/protected-attempt-v0.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture protectedAttemptFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Attempt.NonceCiphertext[0] != loginProtectionVersion || fixture.Attempt.PKCEVerifierCiphertext[0] != loginProtectionVersion {
		t.Fatal("v0.1.0 secret envelope versions changed")
	}
	contextEnvelope, err := base64.RawURLEncoding.Strict().DecodeString(fixture.Attempt.ContextCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if contextEnvelope[0] != attemptContextVersion {
		t.Fatal("v0.1.0 context envelope version changed")
	}

	badNonce := fixture.Attempt.NonceCiphertext
	badNonce[0]++
	if _, err := recoverLoginMaterial(fixture.State, fixture.Attempt.StateHash[:], badNonce[:], fixture.Attempt.PKCEVerifierCiphertext[:]); err == nil {
		t.Fatal("unknown nonce envelope version accepted")
	}
	badVerifier := fixture.Attempt.PKCEVerifierCiphertext
	badVerifier[0]++
	if _, err := recoverLoginMaterial(fixture.State, fixture.Attempt.StateHash[:], fixture.Attempt.NonceCiphertext[:], badVerifier[:]); err == nil {
		t.Fatal("unknown PKCE envelope version accepted")
	}
	badContext := append([]byte(nil), contextEnvelope...)
	badContext[0]++
	if _, err := openAttemptContext(fixture.State, fixture.Attempt.StateHash, badContext); err == nil {
		t.Fatal("unknown attempt-context envelope version accepted")
	}
}
