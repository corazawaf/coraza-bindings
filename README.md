# coraza-bindings

Language bindings for [OWASP Coraza WAF](https://github.com/corazawaf/coraza), built on top of [libcoraza](https://github.com/corazawaf/libcoraza).

## Packages

| Package | Registry | Version |
|---------|----------|---------|
| Python (`coraza`) | PyPI | `python/v*` |
| Java (`org.corazawaf:coraza`) | Maven Central | `java/v*` |

> **Note:** Publishing is not yet enabled. CI builds, tests, and tags are in place.

## Prerequisites

- [libcoraza](https://github.com/corazawaf/libcoraza) built from source (handled automatically by CI via `scripts/fetch-libcoraza.sh`)
- SWIG 4.0+
- Python 3.9+ (for the Python package)
- Java 11+ and Maven 3.8+ (for the Java package)

## Local development

### 1. Build libcoraza

```bash
bash scripts/fetch-libcoraza.sh 1.2.2
# Sets LIBCORAZA_ROOT=/tmp/libcoraza-1.2.2
export LIBCORAZA_ROOT=/tmp/libcoraza-1.2.2
```

### 2. Python

```bash
cd python
pip install scikit-build-core cmake ninja
pip install -e ".[test]"
pytest tests/ -v
```

### 3. Java

```bash
cd java/coraza-java
mvn -B verify
```

## Versioning

Each package has an independent version tracked under `python/` and `java/` respectively.
Releases use prefixed tags: `python/v1.0.0`, `java/v1.0.0`.

Version bumps are managed by [release-please](https://github.com/googleapis/release-please)
and only happen on `main`. Development happens on `develop`.

## Updating libcoraza

When libcoraza releases a new version, an automated PR is opened against `develop`
updating the version pins in `python/libcoraza_version` and `java/libcoraza_version`.
The PR is **never auto-merged** — a maintainer must review and merge it, as upgrades
may require binding code changes.

## Future: Node.js (WASM)

A `nodejs/` package is planned. It will use WebAssembly (Emscripten) rather than
SWIG/native addons, and will follow the same path-filter CI and release-please patterns
as the Python and Java packages.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2024 OWASP Coraza contributors.
