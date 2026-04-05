# coraza-bindings

Language bindings for [OWASP Coraza WAF](https://github.com/corazawaf/coraza), built on top of [libcoraza](https://github.com/corazawaf/libcoraza).

## Packages

| Package | Registry | Version |
|---------|----------|---------|
| Python (`coraza`) | PyPI | `python/v*` |
| Java (`org.corazawaf:coraza`) | Maven Central | `java/v*` |
| Node.js (`@corazawaf/coraza`) | npm | `nodejs/v*` |

> **Note:** Publishing is not yet enabled. CI builds, tests, and tags are in place.

## Prerequisites

**Python / Java** (native bindings via SWIG):
- [libcoraza](https://github.com/corazawaf/libcoraza) built from source (handled automatically by CI via `scripts/fetch-libcoraza.sh`)
- SWIG 4.0+, autoconf, automake, libtool
- Python 3.9+ (Python package) / Java 21+ and Maven 3.8+ (Java package)

**Node.js** (WebAssembly — no native compilation):
- Go ≥ 1.25 (needed to build the WASM module from source)
- Node.js 20+

## Local development

### Python

```bash
bash scripts/fetch-libcoraza.sh main
export LIBCORAZA_ROOT=/tmp/libcoraza-main

cd python
pip install scikit-build-core cmake ninja
pip install -e ".[test]"
pytest tests/ -v
```

### Java

```bash
bash scripts/fetch-libcoraza.sh main
export LIBCORAZA_ROOT=/tmp/libcoraza-main
export JAVA_HOME=$(/usr/libexec/java_home)   # macOS

cd java/coraza-java
mvn -B verify
```

### Node.js

```bash
# Build the WASM module once
bash scripts/build-wasm.sh       # → nodejs/wasm/coraza.wasm

cd nodejs
npm install
npm run build
npm test
```

## Versioning

Each package has an independent version. Releases use prefixed tags:
`python/v1.0.0`, `java/v1.0.0`, `nodejs/v1.0.0`.

Version bumps are managed by [release-please](https://github.com/googleapis/release-please)
and only happen on `main`. Development happens on `develop`.

## Updating libcoraza / coraza

**Python and Java** pin a `libcoraza_version` file and use `scripts/fetch-libcoraza.sh`
to clone the libcoraza C library.

**Node.js** pins `wasm/coraza_version` and `nodejs/coraza_version` (the
`github.com/corazawaf/coraza/v3` Go module version, not libcoraza).

All version bumps are opened as PRs against `develop` and are **never
auto-merged** — a maintainer must review and merge them.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors.

## Author and Maintainer

**Juan Pablo Tosso** <pablo@owasp.org>  
OWASP Coraza project lead and primary maintainer of this repository.
