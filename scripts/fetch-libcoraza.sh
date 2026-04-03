#!/usr/bin/env bash
# fetch-libcoraza.sh <version>
#
# Clones libcoraza at the given version tag and builds it.
# Sets LIBCORAZA_ROOT to the build directory (also written to $GITHUB_ENV if present).
#
# Usage:
#   bash scripts/fetch-libcoraza.sh 1.2.2
#
# After running, LIBCORAZA_ROOT points to a directory containing:
#   libcoraza.a       — static archive for linking
#   coraza/coraza.h   — C header
#
# Note: the SWIG interface file (coraza.i) is bundled with this repo at
# swig/coraza.i and is NOT taken from the libcoraza build output.

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>" >&2
    exit 1
fi

# Strip leading 'v' if present
VERSION="${VERSION#v}"

DEST="${LIBCORAZA_BUILD_DIR:-/tmp/libcoraza-${VERSION}}"

if [[ -f "${DEST}/.built" ]]; then
    echo "libcoraza ${VERSION} already built at ${DEST}, skipping." >&2
else
    echo "Cloning libcoraza v${VERSION} into ${DEST}..." >&2
    rm -rf "${DEST}"
    git clone --depth 1 --branch "v${VERSION}" \
        https://github.com/corazawaf/libcoraza.git "${DEST}"

    echo "Building libcoraza..." >&2
    cd "${DEST}"
    ./build.sh
    ./configure
    make V=1

    touch "${DEST}/.built"
fi

export LIBCORAZA_ROOT="${DEST}"
echo "LIBCORAZA_ROOT=${DEST}"

# Export to GitHub Actions environment if running in CI
if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "LIBCORAZA_ROOT=${DEST}" >> "${GITHUB_ENV}"
fi
