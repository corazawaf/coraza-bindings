# coraza-wasm — Go WASM reactor module

This directory contains the Go source for the WASM binary bundled in
`@corazawaf/coraza` (see `../nodejs/`).

## Build

```bash
# From repository root
bash scripts/build-wasm.sh          # → nodejs/wasm/coraza.wasm

# Custom output path
bash scripts/build-wasm.sh -o /tmp/coraza.wasm
```

Requires Go ≥ 1.25 (coraza/v3 v3.6.0 minimum). `GOTOOLCHAIN=auto` will
download the right toolchain if needed.

## Architecture

The module is a **WASM reactor** (WASI preview1):

- Built with `GOOS=wasip1 GOARCH=wasm -buildmode=c-shared`.
- Exports `_initialize` (not `_start`); the host calls `wasi.initialize(instance)`
  once, then invokes exported functions freely.
- `func main() {}` is present but never called in reactor mode.

### Handle tables

Go objects (WAFConfig, WAF, Transaction, Interruption snapshot) live in
`map[int32]T` tables protected by `sync.Mutex`. JS passes int32 IDs as
"handles" — no pointers cross the WASM boundary.

### String convention

**JS → Go:** JS calls `coraza_malloc(len)`, writes UTF-8 bytes, passes
`(ptr, len)` to the function, then calls `coraza_free(ptr)`.

**Go → JS:** Go writes into a caller-supplied `(outPtr, maxLen)` buffer and
returns the byte count written. `-1` means "absent" (e.g. `intervention.data`
when no redirect URL is set).

### Callbacks

Declared with `//go:wasmimport coraza onError` and `//go:wasmimport coraza
onDebugLog`. JS provides these at `WebAssembly.instantiate` time; the loader
in `nodejs/src/loader.ts` registers no-ops when the user has not opted in.

## Coraza version

`coraza_version` pins `github.com/corazawaf/coraza/v3`. To update:

1. Edit `coraza_version` (and `nodejs/coraza_version`).
2. Run `cd wasm/cmd/coraza-wasm && go get github.com/corazawaf/coraza/v3@<new>`.
3. Rebuild with `bash scripts/build-wasm.sh`.

## License

Apache 2.0 — Copyright 2024 OWASP Coraza contributors
