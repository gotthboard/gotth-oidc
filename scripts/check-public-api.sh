#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
expected="$root/docs/public-api-v1.txt"
actual=$(mktemp)
cd "$root"
raw="$actual.raw"
trap 'rm -f "$actual" "$raw"' EXIT HUP INT TERM
go doc -all ./pkg/oidc >"$raw"
awk 'NF { while (blank > 0) { print ""; blank-- } print; next } { blank++ }' "$raw" >"$actual"
if ! diff -u "$expected" "$actual"; then
  echo "public pkg/oidc API changed; v1 requires an explicit compatibility decision" >&2
  exit 1
fi
