# Deterministic source release build type v1

## Build type

The `scripts/build-release-candidate.sh` build type accepts an exact Git commit
and Go-compatible SemVer tag name; build metadata is rejected. It creates a
deterministic `git archive` source
archive, SPDX 2.3 SBOM, MIT license evidence, an unsigned in-toto statement with
a SLSA provenance v1 predicate, and `SHA256SUMS`. It builds the source archive
twice from an isolated bare Git directory with system/global configuration,
external attributes, repository-local info attributes, replacement refs, and the
archive mode mask and gzip environment controlled; it rejects unequal bytes.
Checked-in `.gitattributes` remain part of
the source contract. The destination must not exist; the builder
validates its selected ref and its own committed bytes, writes only to a private
staging directory, and atomically renames the complete set into place. Failures
remove staging state instead of merging with or overwriting prior evidence.

External parameters are `version` and `ref`. The resolved dependency is the
canonical Forgejo Git commit. The output subjects are the custom source archive,
SBOM, and license-evidence file. No compiler output or binary artifact exists
for this library-only release.

## Local builder

The builder identity denotes the content-addressed recipe in the same commit,
not a trusted hosted build platform. The statement deliberately omits invocation
IDs and execution timestamps so deterministic rebuilds remain byte-identical and
do not claim events that the recipe cannot authenticate. It is unsigned local
provenance: checksums prove internal consistency, not who ran the build. The
SPDX `creationInfo.created` value is the commit timestamp used as a normalized
reproducibility epoch, not a claim about the wall-clock execution time. Release
publication may add a separately signed attestation without changing these
candidate bytes.
