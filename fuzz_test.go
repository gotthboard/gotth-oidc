package oidc

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"testing"
)

func FuzzParseCallback(fuzz *testing.F) {
	fuzz.Add("code=c&state=s")
	fuzz.Add("error=access_denied&state=s")
	fuzz.Add("response=a.b.c")
	fuzz.Fuzz(func(t *testing.T, query string) {
		if len(query) > maxAuthorizationResponseBytes+1 {
			query = query[:maxAuthorizationResponseBytes+1]
		}
		request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "client.example", Path: "/callback", RawQuery: query}}
		_, _ = ParseCallback(request)
	})
}

func FuzzOpenAttemptContext(fuzz *testing.F) {
	fuzz.Add("state", []byte{1, 2, 3})
	fuzz.Add(validEncodedLoginState, []byte{attemptContextVersion})
	fuzz.Fuzz(func(t *testing.T, state string, envelope []byte) {
		if len(state) > 4096 {
			state = state[:4096]
		}
		if len(envelope) > attemptContextMaxBytes+32 {
			envelope = envelope[:attemptContextMaxBytes+32]
		}
		hash := sha256.Sum256([]byte(state))
		_, _ = openAttemptContext(state, hash, envelope)
	})
}

func FuzzParseCompactJWTHeader(fuzz *testing.F) {
	fuzz.Add("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature")
	fuzz.Add("a.b.c")
	fuzz.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16<<10 {
			raw = raw[:16<<10]
		}
		_, _ = parseCompactJWTHeader(raw)
	})
}
