# v1 Compatibility Contract

`v1.0.0` stabilizes the already advertised
`github.com/gotthboard/gotth-oidc/pkg/oidc` package. It does not add a protocol
capability. The exact exported declaration set is checked in at
`docs/public-api-v1.txt` and verified by `scripts/check-public-api.sh`.

## Public Go API

Within v1, exported functions, methods, interfaces, constants, struct field
names and types, and their documented semantics follow Go 1 compatibility.
Additive API remains possible only when it does not weaken existing security or
change zero-value behavior. Application accounts, sessions, cookies,
authorization policy, durable storage, provider operation, implicit flow,
hybrid flow, and protected-resource business clients remain outside this
module.

`AuthorizationError` is the typed error contract. Callers may use `errors.As`
to obtain `*AuthorizationError` and inspect `Code`, `Description`, and `URI`.
Description and URI are bounded but untrusted. Error message strings, including
`AuthorizationError.Error()`, are diagnostics and are not compatibility
contracts; callers must not parse or compare them.

## Persisted ProtectedAttempt values

A deployment may upgrade from v0.1.0 to v1 while v0.1.0 authorization attempts
are still in flight. v1 accepts those values without conversion. The
`ProtectedAttempt` field names, field types, fixed array widths, and default
`encoding/json` representation used by v0.1.0 remain readable in v1.

The persisted value contains three authenticated envelopes:

| Field | v0.1.0 envelope | v1 policy |
| --- | --- | --- |
| `NonceCiphertext` | fixed-width version 1 | read and write version 1 throughout v1 |
| `PKCEVerifierCiphertext` | fixed-width version 1 | read and write version 1 throughout v1 |
| `ContextCiphertext` | base64url of context version 1 | read and write version 1 throughout v1 |

`StateHash` is the unchanged lookup and additional-authenticated-data binding;
it has no independent wire version. Unknown envelope versions, wrong widths,
authentication failures, and malformed encodings fail closed.

A future v1 release that needs a new envelope must first add dual-read support,
continue accepting every v1-emitted envelope for the remainder of v1, and emit
only a documented version. Removing version 1 support requires a new major
version and an explicit drain or migration plan. There is deliberately no
in-place migration API: completing an attempt requires the browser-held state,
and attempts are one-time values that consumers must atomically consume.

The golden fixture at
`pkg/oidc/testdata/protected-attempt-v0.1.0.json` was generated from immutable
v0.1.0 source commit `4c22b248b2e7f03c28051aaf3105a0d769690f73`.
Its SHA-256 is
`79b8a0559e4db4509a743aaf30a513ea2ffe349a81a3616c56bcbc855f79e05f`.
Tests prove JSON round-trip stability, recovery of both secret envelopes,
opening of the context envelope, and rejection of unknown versions for all
three envelopes.
