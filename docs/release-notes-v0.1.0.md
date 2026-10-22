# gotth-oidc v0.1.0

First immutable pre-1.0 release of the hardened OIDC/OAuth relying-party
library used by GOTTH Mail.

## Install

```sh
go get github.com/gotthboard/gotth-oidc/pkg/oidc@v0.1.0
```

```go
import gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
```

## Highlights

- Authorization Code flow with PKCE, state, nonce, callback mix-up defenses,
  strict issuer/end-point validation, and protected attempt contexts.
- ID-token and UserInfo validation, confidential and public clients, refresh
  and revocation, Dynamic Registration, WebFinger, and standardized logout.
- Opt-in JAR, PAR, JARM, DPoP, mutual TLS, and encrypted JWT support with
  adversarial tests and bounded parsing.
- Consumer-owned accounts, sessions, authorization, provider registration,
  key custody, and durable token/logout state remain outside the library.

This is an unstable pre-1.0 API. Verification used Go 1.26.6 and passed format,
vet, race-enabled tests, 90.1% statement coverage, and an external exact-package
consumer. Historical GOTTH Mail evidence covers a live Authorization Code +
PKCE login, exact subject binding, and domain-scoped role enforcement.

## Source and checksum

- Annotated tag object: `0f357d90b4b64da9ef89f8796a766f284e86ba5e`
- Peeled commit: `4c22b248b2e7f03c28051aaf3105a0d769690f73`
- `gotth-oidc-v0.1.0-source.tar.gz` SHA-256:
  `7aa46b124ee71e7106fd7156c1ef3d8bdaf46ec9a0a4e4c4a1497e352e34b7a0`
