# Verification

`make verify` is the required local gate. It pins Go 1.26.6, checks formatting,
runs `go vet`, and runs the complete race-enabled suite with coverage.

The suite covers confidential, public, JWT-authenticated, DPoP, and mutual-TLS
client profiles; required Discovery metadata and defaults; root and split-origin
issuers; callback parsing and mix-up defense; PKCE/state/nonce; token type,
audience, `azp`, issuer, signature, expiry, access-token hash, max-age/auth-time,
and ACR validation; UserInfo; JAR, PAR, JARM, and encrypted JWTs; explicit token
return and refresh; WebFinger and Dynamic Registration; revocation; and all
three standardized logout mechanisms.

Adversarial tests cover redirects, endpoint escape, unsafe algorithms,
cross-JWT substitution, duplicate callback parameters, malformed/oversized
responses, wrong UserInfo subjects, untrusted audiences, invalid client
authentication, attempt-context tampering, DPoP nonce retry and key binding,
registration failures, and secret-redacted formatting.

RFC-complete admission evidence:

- format, vet, race, and module-integrity gates pass;
- statement coverage is 90.1%; remaining branches are enumerated in the
  feature evidence rather than disguised;
- 50 consecutive race-enabled suite repetitions pass;
- three fuzz targets execute 250,446 generated callback, attempt-envelope, and
  JWT-header inputs without a product failure;
- the outside-package API test compiles every public capability family;
- clean-clone and graph evidence are recorded under
  `workflow/features/rfc-complete-oidc/evidence/verification.md`.

Provider integration remains a consumer admission gate because redirect-URI
registration, tenant policy, TLS certificates, key custody, and persistent
token/logout state belong to the consuming application.
