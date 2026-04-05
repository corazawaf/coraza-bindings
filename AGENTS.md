# AGENTS.md — Maintainer and AI-agent guide for coraza-bindings

## Repository overview

`coraza-bindings` is a language-bindings monorepo for
[libcoraza](https://github.com/corazawaf/libcoraza) (the C library wrapping
[OWASP Coraza WAF](https://github.com/corazawaf/coraza)).

```
coraza-bindings/
├── python/          # PyPI package "coraza"
├── java/            # Maven package "org.corazawaf:coraza"
├── wasm/            # Go WASM reactor module (compiled to coraza.wasm)
├── nodejs/          # npm package "@corazawaf/coraza" (bundles coraza.wasm)
├── scripts/         # Shared build helpers
└── .github/         # CI workflows + Dependabot
```

Each package lives in its own sub-directory, has independent semver, and is
CI-isolated via path filters so pushing to `python/**` only triggers
`python.yml`, not `java.yml`.

---

## Architecture decisions

### Language bindings strategy (JNI vs SWIG)

The project uses **SWIG** (not hand-written JNI) for both Python and Java:

| Concern | SWIG (current) | Raw JNI |
|---------|---------------|---------|
| Maintenance cost | Low — one `.i` interface file serves both languages | High — 20+ hand-written C functions per language |
| Type safety | SWIG typemaps handle byte arrays, strings, callbacks | Manual, error-prone |
| Callback support | Custom trampolines in `coraza.i` via `%inline #ifdef` | Full control but complex |
| New language | Reuse `coraza.i` with a new SWIG target | Full rewrite |

The Java build is a **hybrid**: SWIG generates `corazaJNI.java` (raw JNI
bridge) and the wrap C code; handwritten classes (`Waf`, `Transaction`,
`Intervention`) provide the public API.

A single `jni_register.c` file provides a `JNI_OnLoad` that uses
`RegisterNatives` to fix the SWIG-generated callback symbol names so they
match the fully-qualified Java class (`org.corazawaf.coraza.internal.swig.coraza`
vs the SWIG default `coraza`). This is the only place raw JNI is required.

### Node.js / WASM binding strategy

Node.js uses a different approach from Python and Java: Emscripten cannot
compile CGO, so `libcoraza.a` (CGO-based) cannot be used. Instead:

- A standalone Go module (`wasm/cmd/coraza-wasm/`) imports
  `github.com/corazawaf/coraza/v3` directly and compiles to
  `GOOS=wasip1 GOARCH=wasm` with **no CGO**.
- Built with `-buildmode=c-shared`, which produces a **WASM reactor** (exports
  `_initialize` instead of `_start`). Node.js calls `wasi.initialize(instance)`
  once to set up the Go runtime; all exported functions remain callable.
- The `wasm/coraza_version` file pins the `coraza/v3` Go module version (not
  libcoraza). This version is independent of the Python/Java `libcoraza_version`.
- The resulting `coraza.wasm` is bundled inside the `nodejs/` npm package so
  users install a single package with no native compilation step.

**Handle table pattern:** WASM function signatures can only use numeric types.
Go objects (WAFConfig, WAF, Transaction, Interruption) live in `map[int32]T`
tables; JS passes int32 IDs as handles.

**String passing (JS → Go):** JS calls `coraza_malloc(len)`, writes UTF-8
bytes, calls the function with `(ptr, len)`, then calls `coraza_free(ptr)`.

**Callbacks:** Declared via `//go:wasmimport coraza onError` and
`//go:wasmimport coraza onDebugLog`. JS provides no-op defaults if the user
does not register callbacks; they fire with the WAF handle for routing.

**Reactor mode requires Go ≥ 1.25** (coraza/v3 v3.6.0 bumped the minimum).
CI sets `go-version: '>=1.25.0'`.

### libcoraza consumption

`scripts/fetch-libcoraza.sh <version>` clones and builds libcoraza at a pinned
version, then exports `LIBCORAZA_ROOT`. CI caches the build tree with key
`libcoraza-<version>-<OS>-<arch>`.

The static archive `libcoraza.a` is embedded into each language's shared
library at link time (`-Wl,--whole-archive` on Linux, `-Wl,-force_load` on
macOS) so users do not need to install libcoraza separately.

### Versioning

Each package starts at `1.0.0` and follows independent semver:
- Tags: `python/v1.0.0`, `java/v1.0.0`
- release-please manages version bumps via commit messages (`feat:` → minor, `fix:` → patch)
- libcoraza upgrades use `feat: update libcoraza to v<version>` to trigger a minor bump on both packages

### Branching

- `develop` — integration branch; all PRs target this
- `main` — releases only; release-please opens PRs here after merging develop→main

---

## Testing strategy

### Coverage target: ≥ 90% for Python, Java, and Node.js

All public API methods and error paths must be covered. This includes:

| Test scenario | Python file | Java file | Node.js file |
|---|---|---|---|
| Full request/response lifecycle | `test_lifecycle.py` | `WafLifecycleTest.java` | `lifecycle.test.ts` |
| High-level API (Waf creation, callbacks, exceptions) | `test_high_level_api.py` | `WafHighLevelApiTest.java` | `error-handling.test.ts` |
| Request body from file | `test_request_body.py` | `RequestBodyFromFileTest.java` | _(via lifecycle)_ |
| Rules merge | `test_rules_merge.py` | `RulesMergeTest.java` | _(stub)_ |
| Error + debug callbacks | `test_callbacks.py` | `CallbacksTest.java` | `callbacks.test.ts` |
| Intervention: deny + redirect + data field | `test_intervention.py` | `InterventionRedirectTest.java` | `intervention.test.ts` |
| WAF creation error (bad rules) | `test_error_handling.py` | `ErrorHandlingTest.java` | `error-handling.test.ts` |
| Input validation | `test_error_handling.py` | `ErrorHandlingTest.java` | `error-handling.test.ts` |

### Running tests locally

**Prerequisites:**

```bash
# 1. Build libcoraza (skip if already built)
bash scripts/fetch-libcoraza.sh 1.2.2
export LIBCORAZA_ROOT=/tmp/libcoraza-1.2.2

# 2. Java: set JAVA_HOME
export JAVA_HOME=$(/usr/libexec/java_home)   # macOS
# or: export JAVA_HOME=/usr/lib/jvm/temurin-21  # Linux
```

**Python:**

```bash
cd python
pip install scikit-build-core cmake ninja
LIBCORAZA_ROOT=$LIBCORAZA_ROOT pip install -e ".[test]"
pytest tests/ -v --tb=short
```

**Java:**

```bash
cd java/coraza-java
mvn -B verify
```

**Node.js:**

```bash
# Build the WASM module first
bash scripts/build-wasm.sh       # writes nodejs/wasm/coraza.wasm

cd nodejs
npm install
npm run build
npm test
```

### Writing new tests

#### Python guidelines

- Add test functions to the appropriate `python/tests/test_*.py` file.
- Use `pytest.raises` for error paths (not bare `try/except`).
- Use fixtures from `conftest.py` (`deny_waf`, `pass_waf`) to avoid
  boilerplate config+waf+free in every test.
- Always free transactions and WAFs — the C layer has no GC.

#### Java guidelines

- Add `@Test` methods to the appropriate `*Test.java` file.
- Use JUnit 5 assertions (`assertEquals`, `assertNotNull`, `assertThrows`).
- Use `@TempDir` for temp files — JUnit cleans them up automatically.
- All tests cover both the low-level SWIG functions in
  `org.corazawaf.coraza.internal.swig.coraza` (raw SWIG layer) and the
  high-level `Waf`/`Transaction` wrappers (`WafHighLevelApiTest.java`).
- Cast lambdas to the correct callback interface when passing to
  `coraza_set_error_callback` / `coraza_set_debug_log_callback` (which take
  `Object`) to avoid type-inference errors:
  ```java
  coraza.coraza_set_error_callback(cfg, (CorazaErrorCallback) h -> ...);
  ```

#### Node.js guidelines

- Add test functions to the appropriate `nodejs/tests/*.test.ts` file using vitest.
- Each test file uses `beforeAll`/`afterAll` to create/free shared WAF instances.
- Call `_resetForTest()` from `loader.ts` in `afterAll` to clear the WASM singleton
  between test files — otherwise callbacks from one file may bleed into the next.
- Always call `tx.free()` and `waf.free()` in `finally` blocks (no GC for WASM handles).
- Use `Symbol.dispose` / `using` declarations when testing resource cleanup.
- Test both the happy path AND error paths (double-free, use-after-free, invalid rules).

---

## Adding a new language binding

1. Create `<lang>/libcoraza_version` (copy from `python/libcoraza_version`).
2. Create the build glue (e.g. a new `scripts/build-native-<lang>.sh`).
3. Create `.github/workflows/<lang>.yml` with path filters matching `<lang>/**`.
4. Add the language to `release-please-config.json` and `release-please-manifest.json`.
5. Update `update-libcoraza.yml` to also update `<lang>/libcoraza_version`.
6. Update this file with the new test strategy section.

**Note:** The Node.js binding uses WASM (no SWIG, no CGO). It has its own
`coraza_version` pin tracking the Go coraza/v3 module version, independent
of `libcoraza_version` used by Python/Java.

---

## CI workflow reference

| Workflow | Trigger | Purpose |
|---|---|---|
| `python.yml` | push/PR touching `python/**` | Build + test Python package (3 OS × 3 Python) |
| `java.yml` | push/PR touching `java/**` or `scripts/build-native-java.sh` | Build JNI libs, run JUnit 5, assemble fat JAR |
| `wasm.yml` | push/PR touching `wasm/**`, `nodejs/**`, `scripts/build-wasm.sh` | Build WASM reactor, test Node.js (20/22/24) |
| `release-please.yml` | push to `main` | Open release PRs per package |
| `update-libcoraza.yml` | `repository_dispatch` or manual | Open PR bumping version pins — never auto-merges |

### Renovate / Dependabot

- Renovate: PRs only, never auto-merge (`"automerge": false` globally).
- Dependabot: weekly GitHub Actions digest bumps, PRs only.
- libcoraza upgrades: via `update-libcoraza.yml` only, always reviewed manually.

---

## Key files

| File | Purpose |
|---|---|
| `coraza.i` (in libcoraza) | SWIG interface — ships with libcoraza >= v1.3.0; taken from `${LIBCORAZA_ROOT}/coraza.i` |
| `scripts/fetch-libcoraza.sh` | Clone + build libcoraza at pinned version |
| `scripts/build-native-java.sh` | SWIG → JNI compile for Java |
| `scripts/build-wasm.sh` | `GOOS=wasip1 GOARCH=wasm -buildmode=c-shared` build |
| `java/.../jni_register.c` | `JNI_OnLoad` for callback `RegisterNatives` |
| `python/CMakeLists.txt` | CMake + UseSWIG build for Python extension |
| `python/src/coraza/__init__.py` | High-level `Waf`/`Transaction` + re-exports |
| `java/.../Waf.java` | High-level Java API |
| `java/.../NativeLoader.java` | Extracts platform JNI lib from fat JAR at runtime |
| `wasm/cmd/coraza-wasm/main.go` | WASM reactor: handle tables + all `//go:wasmexport` functions |
| `wasm/cmd/coraza-wasm/callbacks.go` | `//go:wasmimport coraza onError/onDebugLog` |
| `nodejs/src/loader.ts` | WASI singleton instantiation + callback wiring |
| `nodejs/src/waf.ts` | High-level `Waf` class |
| `nodejs/src/transaction.ts` | High-level `Transaction` class |

---

## Common pitfalls

- **Python name mangling**: the CMake SWIG target must be named `coraza` (not
  `_coraza`) so the native extension is `_coraza.so` (single underscore).
  Double-underscore names in class bodies get mangled by Python.
- **Java callback symbols**: SWIG generates `Java_coraza_<method>` but the
  packaged class needs `Java_org_..._coraza_<method>`. `JNI_OnLoad` +
  `RegisterNatives` in `jni_register.c` bridges this gap.
- **macOS JNI library**: must be `.dylib` (not `.so`) built with `-dynamiclib`,
  and must embed `libcoraza.a` via `-Wl,-force_load` to be self-contained.
- **LIBCORAZA_ROOT**: must be set before building either package.
- **libcoraza.a embedding**: use `--whole-archive` (Linux) /
  `-force_load` (macOS) to pull in all Go runtime symbols — partial linking
  causes crashes.
