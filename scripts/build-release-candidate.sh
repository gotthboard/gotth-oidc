#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
export PATH

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
worker="$root/scripts/build-release-candidate-worker.sh"
exec env -i PATH="$PATH" HOME=/nonexistent LC_ALL=C TZ=UTC GOENV=off GOTOOLCHAIN=local \
  GIT_NO_REPLACE_OBJECTS=1 "$worker" "$@"
