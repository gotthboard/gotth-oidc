# Release Policy

`gotth-oidc` versions independently under Semantic Versioning. A version number
in another GOTTH repository creates no release obligation here.

If this repository contains a Go module, release tags use the Go-compatible
`vMAJOR.MINOR.PATCH` form, including any SemVer prerelease suffix. Historical
tags are immutable even when they predate this convention.

No release may be tagged until the license decision gate is explicitly closed
and required verification is complete. Reserved placeholders are not tagged at
all.

For an admitted release:

1. Select a version from this repository's actual compatibility change.
2. Verify an exact clean Forgejo commit with the repository's required gates.
3. Update `docs/CHANGELOG.md` with the exact version, commit, compatibility
   effect, verification, and known limitations.
4. Create and push a new annotated tag on canonical Forgejo. Never move or
   replace an existing tag.
5. Verify exact head and tag parity at
   `github.com/gotthboard/gotth-oidc` through the existing one-way push
   mirror.
6. Build any artifacts from the exact public GitHub clone, publish checksums,
   and create the GitHub release for that already-mirrored tag.

Forgejo remains the development source of truth. GitHub is the public clone,
Go import, and release-distribution endpoint. Failure of mirror or release
publication blocks the release; it does not authorize reversing mirror
direction or publishing a different commit.

## Read-only release closeout

The tag fallback URL exists, but the authoritative GitHub release-by-tag API
currently reports no published Release; draft state is unknown without authentication:

```sh
EXPECT_STATE=incomplete sh scripts/release-closeout-check.sh
```

After creating or publishing the normal Release on that immutable tag and uploading the
source archive plus `SHA256SUMS`, require exact metadata and asset bytes:

```sh
EXPECT_STATE=complete sh scripts/release-closeout-check.sh
```

The check requires `git`, `curl`, `python3`, and `sha256sum`. A mismatch
never authorizes moving the tag or replacing tagged source.
