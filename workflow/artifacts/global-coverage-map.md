# Coverage map

| Surface | Evidence |
|---|---|
| Discovery and HTTP boundary | `provider_test.go` |
| Authorization URL and PKCE | `authorization_url_test.go` |
| Code exchange and token verification | `exchange_test.go` |
| Identity admission | `identity_claims_test.go` |
| Attempt generation/protection/recovery | `login_*_test.go` |
| Public API | `api_test.go` |
| External consumer compilation | `public_api_test.go` |
| HTTPS/loopback and signing-algorithm pinning | `provider_test.go`, `exchange_test.go` |
