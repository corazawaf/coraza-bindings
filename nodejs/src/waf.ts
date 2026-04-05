// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import { getCoraza, type CorazaExports, type HostCallbacks } from "./loader.js";
import { Memory } from "./memory.js";
import { Transaction } from "./transaction.js";

/** Options for creating a WAF instance. */
export interface WafOptions {
  /**
   * Inline SecLang rule strings (e.g. `["SecRuleEngine On", "SecRule ..."]`).
   */
  rules?: string[];
  /**
   * Paths to SecLang rule files loaded from the WASI filesystem.
   * Requires WASI preopens to include the directory.
   */
  ruleFiles?: string[];
  /**
   * Called when a rule matches. Receives the raw ErrorLog string.
   * Enable this by setting the option; it registers the WASM callback.
   */
  onRuleMatch?: (ruleLog: string) => void;
  /**
   * Called for each debug log event emitted by the WAF.
   * level follows debuglog.Level: 1=Error, 2=Warn, 3=Info, 4=Debug, 8=Trace.
   */
  onDebugLog?: (level: number, message: string) => void;
}

/**
 * A WAF (Web Application Firewall) instance.
 *
 * Create with `Waf.create(opts)`. Creating a WAF loads the WASM module on the
 * first call; subsequent calls reuse the same WASM instance.
 *
 * ```ts
 * const waf = await Waf.create({ rules: ['SecRuleEngine On'] });
 * const tx = waf.newTransaction();
 * // ... process request/response phases ...
 * tx.free();
 * waf.free();
 * ```
 */
export class Waf {
  readonly #handle: number;
  readonly #exports: CorazaExports;
  readonly #memory: Memory;
  #freed = false;

  private constructor(
    handle: number,
    exports: CorazaExports,
    memory: Memory,
  ) {
    this.#handle = handle;
    this.#exports = exports;
    this.#memory = memory;
  }

  /**
   * Create and initialise a WAF instance.
   * The first call compiles the WASM module; this is cached for subsequent calls.
   *
   * @throws {Error} if the WAF cannot be created (e.g. invalid rules).
   */
  static async create(opts: WafOptions = {}): Promise<Waf> {
    // Register callbacks before loading WASM so the module sees them.
    const cb: HostCallbacks = {};
    if (opts.onRuleMatch) {
      cb.onError = (_waf, msg) => opts.onRuleMatch!(msg);
    }
    if (opts.onDebugLog) {
      cb.onDebugLog = (_waf, level, msg) => opts.onDebugLog!(level, msg);
    }

    const { exports, memory: wasmMemory } = await getCoraza(
      Object.keys(cb).length > 0 ? cb : undefined,
    );
    const mem = new Memory(exports, wasmMemory);

    const cfgHandle = exports.coraza_new_waf_config();
    if (cfgHandle === 0) throw new Error("Failed to create WAF config");

    try {
      if (opts.onRuleMatch) exports.coraza_set_error_callback(cfgHandle);
      if (opts.onDebugLog) exports.coraza_set_debug_log_callback(cfgHandle);

      for (const rule of opts.rules ?? []) {
        mem.withString(rule, (ptr, len) =>
          exports.coraza_rules_add(cfgHandle, ptr, len),
        );
      }
      for (const path of opts.ruleFiles ?? []) {
        mem.withString(path, (ptr, len) =>
          exports.coraza_rules_add_file(cfgHandle, ptr, len),
        );
      }

      const wafHandle = exports.coraza_new_waf(cfgHandle);
      if (wafHandle === 0)
        throw new Error(
          "Failed to create WAF — check rule syntax and file paths",
        );

      return new Waf(wafHandle, exports, mem);
    } finally {
      exports.coraza_free_waf_config(cfgHandle);
    }
  }

  /** Number of rules loaded in this WAF. */
  get rulesCount(): number {
    this.#assertAlive();
    return this.#exports.coraza_rules_count(this.#handle);
  }

  /** Create a new transaction for processing an HTTP request/response. */
  newTransaction(): Transaction {
    this.#assertAlive();
    const handle = this.#exports.coraza_new_transaction(this.#handle);
    if (handle === 0) throw new Error("Failed to create transaction");
    return new Transaction(this.#exports, this.#memory, handle);
  }

  /** Create a new transaction with a caller-supplied ID (for correlation). */
  newTransactionWithId(id: string): Transaction {
    this.#assertAlive();
    const handle = this.#memory.withString(id, (ptr, len) =>
      this.#exports.coraza_new_transaction_with_id(this.#handle, ptr, len),
    );
    if (handle === 0) throw new Error("Failed to create transaction");
    return new Transaction(this.#exports, this.#memory, handle);
  }

  /** Release the WAF handle. Existing transactions are unaffected. */
  free(): void {
    if (!this.#freed) {
      this.#freed = true;
      this.#exports.coraza_free_waf(this.#handle);
    }
  }

  [Symbol.dispose](): void {
    this.free();
  }

  #assertAlive(): void {
    if (this.#freed) throw new Error("WAF already freed");
  }
}
