#!/usr/bin/env bash
# Builds ONE binary (linux/amd64 unless GOOS/GOARCH are set, e.g. GOOS=darwin GOARCH=arm64) with the Yandex.Disk OAuth credentials baked in.
# The credentials are read from the sozvon-konspekt env file at build time; they end up only inside the binary.
# Usage: bash build.sh [path/to/env-file]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${1:-$HERE/../sozvon-konspekt/.env.95-182-83-180}"

get() {
  grep -m1 "^$1=" "$ENV_FILE" | sed -e 's/^[^=]*=//' -e 's/\r$//' -e 's/^"\(.*\)"$/\1/'
}

CLIENT_ID="$(get YADISK_CLIENT_ID)"
CLIENT_SECRET="$(get YADISK_CLIENT_SECRET)"
REFRESH_TOKEN="$(get YADISK_REFRESH_TOKEN)"
for name in CLIENT_ID CLIENT_SECRET REFRESH_TOKEN; do
  [[ -n "${!name}" ]] || { echo "YADISK_${name} is missing in $ENV_FILE" >&2; exit 1; }
done

mkdir -p "$HERE/bin"
cd "$HERE"
CGO_ENABLED=0 GOOS="${GOOS:-linux}" GOARCH="${GOARCH:-amd64}" go build -trimpath \
  -ldflags "-s -w -X main.clientID=$CLIENT_ID -X main.clientSecret=$CLIENT_SECRET -X main.refreshToken=$REFRESH_TOKEN" \
  -o bin/yadisk-download .
chmod 700 bin/yadisk-download
echo "built $HERE/bin/yadisk-download (${GOOS:-linux}/${GOARCH:-amd64}, contains secrets: do not share)"
