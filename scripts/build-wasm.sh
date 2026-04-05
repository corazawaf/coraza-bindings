#!/usr/bin/env bash
# build-wasm.sh — Build the coraza WASM reactor module.
#
# Usage:
#   bash scripts/build-wasm.sh                  # output to nodejs/wasm/coraza.wasm
#   bash scripts/build-wasm.sh -o path/out.wasm # custom output path
#
# Requires Go >= 1.25 (GOTOOLCHAIN=auto will download it if needed).
# The resulting .wasm is a WASI reactor (exports _initialize, not _start).

set -euo pipefail

OUTPUT="nodejs/wasm/coraza.wasm"

# Parse optional -o flag
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) OUTPUT="$2"; shift 2 ;;
        *)  echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

mkdir -p "$(dirname "${REPO_ROOT}/${OUTPUT}")"

echo "Building coraza WASM reactor module..." >&2
cd "${REPO_ROOT}/wasm/cmd/coraza-wasm"

GOOS=wasip1 GOARCH=wasm go build \
    -buildmode=c-shared \
    -trimpath \
    -ldflags="-s -w" \
    -o "${REPO_ROOT}/${OUTPUT}" \
    .

SIZE=$(wc -c < "${REPO_ROOT}/${OUTPUT}")
echo "Built: ${OUTPUT} (${SIZE} bytes)" >&2
