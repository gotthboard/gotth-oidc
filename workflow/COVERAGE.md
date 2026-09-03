# Coverage

The canonical behavior map is `workflow/artifacts/global-coverage-map.md`.
`make verify` runs hostile, negative, RFC-capability, fuzz-seed, and
outside-package tests under `pkg/oidc`. Current statement coverage is 90.1%.
The recorded remainder is defensive handling around injected dependencies and
standard-library failures, not an unlisted protocol capability.
