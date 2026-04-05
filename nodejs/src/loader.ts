// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import { WASI } from "node:wasi";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** All functions exported from the coraza WASM reactor module. */
export interface CorazaExports {
  // Memory
  coraza_malloc(size: number): number;
  coraza_free(ptr: number): void;
  // WAF config
  coraza_new_waf_config(): number;
  coraza_rules_add(cfg: number, ptr: number, len: number): number;
  coraza_rules_add_file(cfg: number, ptr: number, len: number): number;
  coraza_set_error_callback(cfg: number): number;
  coraza_set_debug_log_callback(cfg: number): number;
  coraza_free_waf_config(cfg: number): void;
  // WAF
  coraza_new_waf(cfg: number): number;
  coraza_rules_count(waf: number): number;
  coraza_rules_merge(dst: number, src: number): number;
  coraza_free_waf(waf: number): void;
  // Transaction
  coraza_new_transaction(waf: number): number;
  coraza_new_transaction_with_id(waf: number, ptr: number, len: number): number;
  coraza_process_connection(
    tx: number,
    clientPtr: number,
    clientLen: number,
    clientPort: number,
    serverPtr: number,
    serverLen: number,
    serverPort: number,
  ): number;
  coraza_process_uri(
    tx: number,
    uriPtr: number,
    uriLen: number,
    methodPtr: number,
    methodLen: number,
    protoPtr: number,
    protoLen: number,
  ): number;
  coraza_add_request_header(
    tx: number,
    namePtr: number,
    nameLen: number,
    valPtr: number,
    valLen: number,
  ): number;
  coraza_add_get_args(
    tx: number,
    namePtr: number,
    nameLen: number,
    valPtr: number,
    valLen: number,
  ): number;
  coraza_process_request_headers(tx: number): number;
  coraza_append_request_body(
    tx: number,
    dataPtr: number,
    dataLen: number,
  ): number;
  coraza_process_request_body(tx: number): number;
  coraza_request_body_from_file(
    tx: number,
    pathPtr: number,
    pathLen: number,
  ): number;
  coraza_process_response_headers(
    tx: number,
    status: number,
    protoPtr: number,
    protoLen: number,
  ): number;
  coraza_add_response_header(
    tx: number,
    namePtr: number,
    nameLen: number,
    valPtr: number,
    valLen: number,
  ): number;
  coraza_append_response_body(
    tx: number,
    dataPtr: number,
    dataLen: number,
  ): number;
  coraza_process_response_body(tx: number): number;
  coraza_update_status_code(tx: number, code: number): number;
  coraza_process_logging(tx: number): number;
  coraza_free_transaction(tx: number): void;
  // Intervention
  coraza_intervention(tx: number): number;
  coraza_intervention_get_status(it: number): number;
  coraza_intervention_get_action(
    it: number,
    outPtr: number,
    maxLen: number,
  ): number;
  coraza_intervention_get_data(
    it: number,
    outPtr: number,
    maxLen: number,
  ): number;
  coraza_free_intervention(it: number): void;
}

/**
 * Callbacks provided by the JS host and forwarded from the WASM module.
 */
export interface HostCallbacks {
  /**
   * Called when a rule fires and the WAF was configured with onRuleMatch.
   * wafHandle identifies which WAF instance matched.
   */
  onError?: (wafHandle: number, message: string) => void;
  /**
   * Called for each debug log event when onDebugLog was registered.
   * level: 1=Error, 2=Warn, 3=Info, 4=Debug, 8=Trace (debuglog.Level).
   */
  onDebugLog?: (wafHandle: number, level: number, message: string) => void;
}

export interface CorazaInstance {
  exports: CorazaExports;
  memory: WebAssembly.Memory;
}

let cached: Promise<CorazaInstance> | null = null;
let callbacks: HostCallbacks = {};

/**
 * Returns (and caches) the initialised WASM instance.
 * The first call compiles and instantiates the WASM module; subsequent calls
 * return the cached instance.
 *
 * Callbacks must be registered before the first getCoraza() call or they
 * will be silently ignored for that instance.
 */
export function getCoraza(cb?: HostCallbacks): Promise<CorazaInstance> {
  if (cb) Object.assign(callbacks, cb);
  if (!cached) cached = _load();
  return cached;
}

/** Reset the cached instance (for testing only). */
export function _resetForTest(): void {
  cached = null;
  callbacks = {};
}

async function _load(): Promise<CorazaInstance> {
  // __dirname is available in CJS; tsup injects a shim for ESM builds.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dir: string = (globalThis as any).__dirname ?? __dirname;
  const wasmPath = join(dir, "..", "wasm", "coraza.wasm");
  const wasmBytes = readFileSync(wasmPath);

  const wasi = new WASI({ version: "preview1", preopens: { "/": "/" } });

  // instance is assigned after instantiation; closures capture it by reference.
  let instance!: WebAssembly.Instance;

  const decoder = new TextDecoder();

  function readMsg(
    mem: WebAssembly.Memory,
    ptr: number,
    len: number,
  ): string {
    return decoder.decode(new Uint8Array(mem.buffer, ptr, len));
  }

  const imports = {
    wasi_snapshot_preview1: wasi.wasiImport,
    coraza: {
      onError(wafHandle: number, msgPtr: number, msgLen: number): void {
        const mem = instance.exports["memory"] as WebAssembly.Memory;
        callbacks.onError?.(wafHandle, readMsg(mem, msgPtr, msgLen));
      },
      onDebugLog(
        wafHandle: number,
        level: number,
        msgPtr: number,
        msgLen: number,
      ): void {
        const mem = instance.exports["memory"] as WebAssembly.Memory;
        callbacks.onDebugLog?.(wafHandle, level, readMsg(mem, msgPtr, msgLen));
      },
    },
  };

  const module = await WebAssembly.compile(wasmBytes);
  instance = await WebAssembly.instantiate(module, imports);
  wasi.initialize(instance);

  const exports = instance.exports as unknown as CorazaExports;
  const memory = instance.exports["memory"] as WebAssembly.Memory;
  return { exports, memory };
}
