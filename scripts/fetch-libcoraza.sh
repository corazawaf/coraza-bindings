#!/usr/bin/env bash
# fetch-libcoraza.sh <version-or-branch>
#
# Clones libcoraza at a version tag or branch name and builds it.
# Sets LIBCORAZA_ROOT to the build directory (also written to $GITHUB_ENV if present).
#
# Usage:
#   bash scripts/fetch-libcoraza.sh 1.2.2    # clones tag v1.2.2
#   bash scripts/fetch-libcoraza.sh main      # clones branch main
#
# After running, LIBCORAZA_ROOT points to a directory containing:
#   libcoraza.a       — static archive for linking
#   coraza/coraza.h   — C header
#   coraza.i          — SWIG interface file (present on main; tagged in >= v1.3.0)
#
# Note: for branch refs (e.g. "main"), the .built sentinel is not used because
# the branch tip may have changed. Delete the destination directory manually to
# force a rebuild when using a branch ref during local development.

set -euo pipefail

REF="${1:-}"
if [[ -z "$REF" ]]; then
    echo "Usage: $0 <version-or-branch>" >&2
    exit 1
fi

# Determine the git ref to clone:
# - Semver (starts with a digit or 'v'): treat as a release tag, prefix with 'v'
# - Anything else (main, develop, a SHA prefix): use as-is
if [[ "${REF}" =~ ^[0-9] ]]; then
    GIT_REF="v${REF}"
    IS_TAG=true
elif [[ "${REF}" =~ ^v[0-9] ]]; then
    GIT_REF="${REF}"
    REF="${REF#v}"   # strip 'v' for the directory name
    IS_TAG=true
else
    GIT_REF="${REF}"
    IS_TAG=false
fi

DEST="${LIBCORAZA_BUILD_DIR:-/tmp/libcoraza-${REF}}"

# For tags, skip rebuild if already built. For branches, always rebuild.
if [[ "${IS_TAG}" == true && -f "${DEST}/.built" ]]; then
    echo "libcoraza ${REF} already built at ${DEST}, skipping." >&2
else
    echo "Cloning libcoraza ${GIT_REF} into ${DEST}..." >&2
    rm -rf "${DEST}"
    git clone --depth 1 --branch "${GIT_REF}" \
        https://github.com/corazawaf/libcoraza.git "${DEST}"

    echo "Building libcoraza..." >&2
    cd "${DEST}"
    ./build.sh
    ./configure
    make V=1

    if [[ "${IS_TAG}" == true ]]; then
        touch "${DEST}/.built"
    fi
fi

export LIBCORAZA_ROOT="${DEST}"
echo "LIBCORAZA_ROOT=${DEST}"

# Export to GitHub Actions environment if running in CI
if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "LIBCORAZA_ROOT=${DEST}" >> "${GITHUB_ENV}"
fi
