# Verification evidence

## Exact state

- Structural implementation: `5546da8c4464050b1e4b1b273a6a687aacbdb2d8`.
- Corrected review candidate: `96561f5362cc7a12bae484b943e87e8461d1b1fd`.
- Base/distribution prerequisite: `a042e92fd6fde6798464b8c5d1b833d5a472b0ad`.
- Canonical package: `github.com/gotthboard/gotth-oidc/pkg/oidc`.

## Coding-setup admission

- Root byte/inode preflight: 5% bytes, 1% inodes; below both stop thresholds.
- Context broker 0.1.0: clean revision, cache miss, untruncated bounded packet;
  cache path `/home/linus/.cache/openclaw-code-context/2fb368d77ff44f33/78dcfaf5d79b4e10/0fe39734a6e7d12b8b67f85a620401f55d1787cabe55e85e22d49bc2560a92b9.json`.
- Production units were not changed: every implementation file is a 100%
  content-identical rename. Prospective complexity comments are N/A.
- Performance admission: N/A. Cryptography, allocations, payload bounds,
  network round trips, parsing, and endpoint policy are unchanged; no speedup
  is claimed.
- Runtime contract: Go 1.26.6, pinned OAuth/OIDC/JOSE dependencies, the RFC
  matrix in `docs/conformance.md`, bounded hostile inputs, and explicit
  consumer authority for durable attempt/token/replay state and TLS.
- `gopls` was unavailable and was not installed; compiler, vet, tests, fuzz,
  and outside-package compilation provide the applicable language evidence.

## Verification

- `go mod verify && make verify`: PASS; statement coverage 90.1%.
- Fifty consecutive `go test -mod=readonly -race ./...` runs: PASS.
- Five-second fuzz admissions: callback 33,299, protected-attempt 43,827, JWT
  header 41,238; 118,364 total generated inputs, all PASS.
- RFC, hostile-provider, mix-up, JOSE, callback, client-authentication, DPoP,
  mTLS, registration, token, and logout suites: PASS.
- Module root contains zero Go files; canonical outside-consumer import: PASS.
- Two independent cold Judge passes on one exact committed state: CLEAN.
- No live provider, credential, token, tag, or deployment changed.

## Graph evidence

Graphify 0.9.32, code-only, implementation revision
`5546da8c4464050b1e4b1b273a6a687aacbdb2d8`:

- path: `/home/linus/.cache/openclaw-code-index/gotth-oidc/5546da8c4464050b1e4b1b273a6a687aacbdb2d8/graphify/graphify-out/graph.json`
- SHA-256: `f740197c1e6529022da0b23f995dc6fbe440cf409b31c0f6462f42aa13005897`
- 339 nodes, 793 edges, 18 communities; zero self-loops, duplicates,
  same-endpoint collisions, or dangling endpoints.

Graph findings were verified in source and by compiler/protocol tests.
