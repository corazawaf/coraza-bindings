// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import type { CorazaExports } from "./loader.js";
import { Memory } from "./memory.js";
import { type Intervention, readIntervention } from "./intervention.js";

/** A single HTTP transaction evaluated by the WAF. Not thread-safe. */
export class Transaction {
  readonly #exports: CorazaExports;
  readonly #memory: Memory;
  readonly #handle: number;
  #freed = false;

  /** @internal */
  constructor(exports: CorazaExports, memory: Memory, handle: number) {
    this.#exports = exports;
    this.#memory = memory;
    this.#handle = handle;
  }

  #check(): void {
    if (this.#freed) throw new Error("Transaction already freed");
  }

  #intervention(rc: number): Intervention | null {
    if (rc < 0)
      throw new Error(`coraza WASM error (code ${rc})`);
    if (rc === 0) return null;
    const itHandle = this.#exports.coraza_intervention(this.#handle);
    if (itHandle === 0) return null;
    return readIntervention(this.#exports, this.#memory, itHandle);
  }

  /** Record connection metadata. */
  processConnection(
    clientIp: string,
    clientPort: number,
    serverIp: string,
    serverPort: number,
  ): void {
    this.#check();
    this.#memory.withStrings(clientIp, serverIp, (cPtr, cLen, sPtr, sLen) =>
      this.#exports.coraza_process_connection(
        this.#handle,
        cPtr,
        cLen,
        clientPort,
        sPtr,
        sLen,
        serverPort,
      ),
    );
  }

  /** Record the request URI, method, and HTTP version. */
  processUri(uri: string, method: string, httpVersion: string): void {
    this.#check();
    const u = this.#memory.writeString(uri);
    const m = this.#memory.writeString(method);
    const p = this.#memory.writeString(httpVersion);
    try {
      this.#exports.coraza_process_uri(
        this.#handle,
        u.ptr,
        u.len,
        m.ptr,
        m.len,
        p.ptr,
        p.len,
      );
    } finally {
      this.#memory.free(u.ptr);
      this.#memory.free(m.ptr);
      this.#memory.free(p.ptr);
    }
  }

  /** Add a request header. */
  addRequestHeader(name: string, value: string): void {
    this.#check();
    this.#memory.withStrings(name, value, (nPtr, nLen, vPtr, vLen) =>
      this.#exports.coraza_add_request_header(
        this.#handle,
        nPtr,
        nLen,
        vPtr,
        vLen,
      ),
    );
  }

  /** Add a GET query-string argument. */
  addGetArgument(name: string, value: string): void {
    this.#check();
    this.#memory.withStrings(name, value, (nPtr, nLen, vPtr, vLen) =>
      this.#exports.coraza_add_get_args(
        this.#handle,
        nPtr,
        nLen,
        vPtr,
        vLen,
      ),
    );
  }

  /** Evaluate request headers. Returns an intervention if a rule matched. */
  processRequestHeaders(): Intervention | null {
    this.#check();
    const rc = this.#exports.coraza_process_request_headers(this.#handle);
    return this.#intervention(rc);
  }

  /**
   * Write a chunk of the request body. Returns an intervention if a body limit
   * was exceeded and action is to reject.
   */
  appendRequestBody(data: Uint8Array | string): Intervention | null {
    this.#check();
    const bytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    const rc = this.#memory.withBytes(bytes, (ptr, len) =>
      this.#exports.coraza_append_request_body(this.#handle, ptr, len),
    );
    return this.#intervention(rc);
  }

  /** Evaluate the full request body. */
  processRequestBody(): Intervention | null {
    this.#check();
    const rc = this.#exports.coraza_process_request_body(this.#handle);
    return this.#intervention(rc);
  }

  /** Stream a file into the request body buffer and evaluate it. */
  requestBodyFromFile(path: string): Intervention | null {
    this.#check();
    const rc = this.#memory.withString(path, (ptr, len) =>
      this.#exports.coraza_request_body_from_file(this.#handle, ptr, len),
    );
    return this.#intervention(rc);
  }

  /** Add a response header. */
  addResponseHeader(name: string, value: string): void {
    this.#check();
    this.#memory.withStrings(name, value, (nPtr, nLen, vPtr, vLen) =>
      this.#exports.coraza_add_response_header(
        this.#handle,
        nPtr,
        nLen,
        vPtr,
        vLen,
      ),
    );
  }

  /** Evaluate response headers. */
  processResponseHeaders(status: number, proto: string): Intervention | null {
    this.#check();
    const rc = this.#memory.withString(proto, (ptr, len) =>
      this.#exports.coraza_process_response_headers(
        this.#handle,
        status,
        ptr,
        len,
      ),
    );
    return this.#intervention(rc);
  }

  /** Write a chunk of the response body. */
  appendResponseBody(data: Uint8Array | string): Intervention | null {
    this.#check();
    const bytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    const rc = this.#memory.withBytes(bytes, (ptr, len) =>
      this.#exports.coraza_append_response_body(this.#handle, ptr, len),
    );
    return this.#intervention(rc);
  }

  /** Evaluate the full response body. */
  processResponseBody(): Intervention | null {
    this.#check();
    const rc = this.#exports.coraza_process_response_body(this.#handle);
    return this.#intervention(rc);
  }

  /**
   * Update the transaction's tracked response status code.
   * Used by reverse-proxy integrations when the upstream status is known.
   */
  updateStatusCode(code: number): void {
    this.#check();
    this.#exports.coraza_update_status_code(this.#handle, code);
  }

  /** Run the logging phase. Should be called once per transaction lifecycle. */
  processLogging(): void {
    this.#check();
    this.#exports.coraza_process_logging(this.#handle);
  }

  /**
   * Return the current intervention without advancing the transaction state.
   * Null if the transaction has not been interrupted.
   */
  intervention(): Intervention | null {
    this.#check();
    const itHandle = this.#exports.coraza_intervention(this.#handle);
    if (itHandle === 0) return null;
    return readIntervention(this.#exports, this.#memory, itHandle);
  }

  /**
   * Release the native transaction handle.
   * Calls processLogging() automatically if not already called.
   * Must be called exactly once; subsequent calls are no-ops.
   */
  free(): void {
    if (!this.#freed) {
      this.#freed = true;
      this.#exports.coraza_free_transaction(this.#handle);
    }
  }

  [Symbol.dispose](): void {
    this.free();
  }
}
