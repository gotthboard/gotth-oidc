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

## v1 source release candidate

v1 stabilizes only the existing `pkg/oidc` contract. Protocol expansion,
consumer migrations, tagging, pushing, hosted Release creation, and deployment
are separate outcomes.

From an exact committed candidate, build the source release set outside the
repository:

    scripts/build-release-candidate.sh v1.0.0 OUTPUT_DIR COMMIT
    (cd OUTPUT_DIR && sha256sum -c SHA256SUMS)

The builder verifies a byte-identical second source-archive build and requires
its own bytes to match the selected commit. Its deterministic provenance is an
unsigned local statement, not a trusted-platform or signer claim; the exact
semantics are in `docs/release-build-type-v1.md`. The release set consists of the
source archive, SPDX 2.3 SBOM, license evidence, in-toto/SLSA provenance, and
`SHA256SUMS`. The source archive must contain the repository MIT `LICENSE`.
Generated evidence is candidate-bound and must not be committed back into the
candidate it describes.

Before an immutable v1 tag, require:

1. the public API snapshot and v0.1.0 persisted-attempt golden checks;
2. format, read-only module, vet, race, coverage, repeat, fuzz, clean-clone, and
   exact external-consumer checks on one commit;
3. deterministic release-set reproduction and semantic validation of the SBOM,
   provenance subjects, checksum manifest, and license evidence;
4. two fresh cold reviews of that exact commit and sealed evidence; and
5. separately verified publication identity, signing prerequisites, canonical
   Forgejo state, and mirror behavior.

No prepared candidate, checksum, or release note authorizes a push, tag, hosted
Release, or support-status change. Publication defects require a successor
version; immutable refs and published assets are never rewritten.
