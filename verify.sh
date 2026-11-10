#!/bin/sh
# Rebuild the release binaries in the pinned container and compare with the
# published hashes: ./verify.sh [SHA256SUMS-from-the-release]
set -eu
cd "$(dirname "$0")"
docker build --target build -t unlinkable-verify .
id=$(docker create unlinkable-verify)
docker cp "$id:/out/SHA256SUMS" ./SHA256SUMS.rebuilt
docker rm "$id" >/dev/null
cat SHA256SUMS.rebuilt
if [ $# -ge 1 ]; then
  if diff -u "$1" SHA256SUMS.rebuilt; then echo "Identical to $1."; else echo "DIFFERENT from $1." >&2; exit 1; fi
fi
