#!/usr/bin/env bash
# build-native-java.sh
#
# Generates the Java SWIG wrapper and compiles the JNI shared library.
# Called by Maven's exec-maven-plugin during generate-resources phase.
#
# Required environment variables:
#   LIBCORAZA_ROOT  — path to a built libcoraza tree (from fetch-libcoraza.sh)
#   OUTPUT_DIR      — directory to place the JNI lib and generated Java sources
#   JAVA_HOME       — JDK root (must be set)

set -euo pipefail

: "${LIBCORAZA_ROOT:?LIBCORAZA_ROOT must be set}"
: "${OUTPUT_DIR:?OUTPUT_DIR must be set}"
: "${JAVA_HOME:?JAVA_HOME must be set}"

LIBCORAZA_A="${LIBCORAZA_ROOT}/libcoraza.a"
# coraza.i ships with libcoraza starting from v1.3.0.
CORAZA_I="${LIBCORAZA_ROOT}/coraza.i"
CORAZA_H="${LIBCORAZA_ROOT}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

JAVA_GEN="${OUTPUT_DIR}/java-gen"
mkdir -p "${OUTPUT_DIR}" "${JAVA_GEN}"

# Detect platform
OS="$(uname -s)"

if [[ "${OS}" == "Darwin" ]]; then
    JNI_INCLUDE="${JAVA_HOME}/include"
    JNI_INCLUDE_PLAT="${JAVA_HOME}/include/darwin"
    JNI_LIB="${OUTPUT_DIR}/libcoraza_jni.dylib"
    LDFLAGS="-dynamiclib -Wl,-force_load,${LIBCORAZA_A} -framework CoreFoundation -framework Security -lresolv"
elif [[ "${OS}" == "Linux" ]]; then
    JNI_INCLUDE="${JAVA_HOME}/include"
    JNI_INCLUDE_PLAT="${JAVA_HOME}/include/linux"
    JNI_LIB="${OUTPUT_DIR}/libcoraza_jni.so"
    LDFLAGS="-shared -Wl,--whole-archive ${LIBCORAZA_A} -Wl,--no-whole-archive -lpthread -ldl"
else
    echo "Unsupported OS: ${OS}" >&2
    exit 1
fi

echo "Running SWIG for Java..." >&2
swig -java -package org.corazawaf.coraza.internal.swig \
    -outdir "${JAVA_GEN}" \
    -o "${OUTPUT_DIR}/coraza_wrap.c" \
    "${CORAZA_I}"

JNI_REGISTER="${SCRIPT_DIR}/../java/coraza-java/src/main/native/jni_register.c"

echo "Compiling JNI shared library..." >&2
# shellcheck disable=SC2086
gcc -fPIC \
    -I"${CORAZA_H}" \
    -I"${JNI_INCLUDE}" \
    -I"${JNI_INCLUDE_PLAT}" \
    ${LDFLAGS} \
    -o "${JNI_LIB}" \
    "${OUTPUT_DIR}/coraza_wrap.c" \
    "${JNI_REGISTER}"

echo "JNI library built: ${JNI_LIB}" >&2
echo "SWIG Java sources in: ${JAVA_GEN}" >&2
