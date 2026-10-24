#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
builder="$root/scripts/build-release-candidate.sh"
sh -n "$builder"

for invalid in v1x.0.0 v1.0.0evil v1.0.0/extra 1.0.0 v01.0.0 v1.0.0-01 v1.0.0-rc.01; do
  if "$builder" "$invalid" /tmp/gotth-oidc-invalid-release-version HEAD >/dev/null 2>&1; then
    echo "release builder accepted invalid version: $invalid" >&2
    exit 1
  fi
done

probe="$root/.release-output-probe"
if [ -e "$probe" ]; then
  echo "release output probe path already exists: $probe" >&2
  exit 1
fi
if output=$("$builder" v1.0.0 "$probe" HEAD 2>&1); then
  echo "release builder accepted an output directory inside the repository" >&2
  exit 1
fi
case "$output" in
  *"OUTPUT_DIR must be outside the source repository"*) ;;
  *) echo "release builder rejected in-tree output for the wrong reason: $output" >&2; exit 1 ;;
esac
if [ -e "$probe" ]; then
  echo "release builder mutated the repository before rejecting its output path" >&2
  exit 1
fi

if grep -R -n -E 'Error[(][)][[:space:]]*(==|!=)' "$root/pkg/oidc" --include='*_test.go'; then
  echo "test makes diagnostic error text contractual" >&2
  exit 1
fi
