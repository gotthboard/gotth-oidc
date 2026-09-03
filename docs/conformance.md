# Conformance matrix

The normative baseline is OpenID Connect Core 1.0 and Discovery 1.0, OAuth 2.0
(RFC 6749), PKCE (RFC 7636), authorization-server metadata (RFC 8414), issuer
identification (RFC 9207), and OAuth security best current practice (RFC 9700).

The optional implemented profiles are Dynamic Registration, RP-Initiated
Logout, Back-Channel Logout, PAR (RFC 9126), JAR (RFC 9101), JWT authorization
responses, JWT client authentication (RFC 7523), mutual TLS (RFC 8705), and DPoP
(RFC 9449).

| Capability | Default | Admission rule |
|---|---:|---|
| Authorization Code + S256 PKCE/state/nonce | on | exact one-time attempt and token validation |
| Discovery defaults and required metadata | on | malformed or incompatible metadata rejected |
| Audience, `azp`, token type, RFC 9207 issuer | on | fail closed; multi-audience needs explicit trust |
| Query and `form_post` callbacks/errors | on | bounded, duplicate-free typed parser |
| Split-origin/query endpoints | policy | every endpoint independently allowlisted |
| UserInfo and optional profile claims | opt-in | bounded response and exact `sub` equality |
| Claims, prompt, max-age/auth-time, ACR, locales/hints | opt-in | request and validation policy bound to attempt |
| PAR, JAR, JARM, encrypted JWTs | opt-in | provider support and purpose-bound JOSE required |
| Token return, offline access, refresh | opt-in | caller explicitly assumes token custody |
| Dynamic registration and WebFinger | direct API | bounded HTTPS operations and exact issuer checks |
| RP-initiated/back-channel logout | opt-in | state/audience/events/time validation |
| DPoP and mutual TLS | opt-in | code bound with `dpop_jkt`; proofs and endpoint aliases enforced |

Implicit and Hybrid flows remain deliberately unsupported: RFC 9700 deprecates
or discourages response types that expose access tokens or ID tokens through the
authorization endpoint. Token introspection and generic protected-resource API
clients remain OAuth resource-client concerns, not OIDC login requirements.
