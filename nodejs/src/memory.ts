// Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
// SPDX-License-Identifier: Apache-2.0

import type { CorazaExports } from "./loader.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Memory helpers for passing strings across the WASM boundary.
 *
 * Convention (JS → Go):
 *   1. Call coraza_malloc(byteLength) to allocate a buffer in WASM memory.
 *   2. Write UTF-8 bytes into the returned pointer.
 *   3. Call the WASM function with (ptr, len).
 *   4. Call coraza_free(ptr) when done.
 *
 * Convention (Go → JS):
 *   A caller-supplied (outPtr, maxLen) buffer is written by Go. The function
 *   returns the number of bytes written, or -1 to indicate "absent".
 */
export class Memory {
  constructor(
    private readonly exports: CorazaExports,
    private readonly wasmMemory: WebAssembly.Memory,
  ) {}

  /** Allocate `size` bytes in WASM linear memory. Caller must call free(). */
  alloc(size: number): number {
    const ptr = this.exports.coraza_malloc(size);
    if (ptr === 0) throw new Error("coraza_malloc returned null");
    return ptr;
  }

  /** Release memory previously returned by alloc(). */
  free(ptr: number): void {
    this.exports.coraza_free(ptr);
  }

  /**
   * Write `str` into a freshly allocated WASM buffer.
   * The caller must call free(ptr) after use.
   */
  writeString(str: string): { ptr: number; len: number } {
    const bytes = encoder.encode(str);
    const len = bytes.length;
    // Allocate at least 1 byte so we never pass a null pointer.
    const ptr = this.alloc(len || 1);
    if (len > 0) {
      // Re-read the view after alloc because memory may have grown.
      new Uint8Array(this.wasmMemory.buffer, ptr, len).set(bytes);
    }
    return { ptr, len };
  }

  /** Read `len` bytes at `ptr` from WASM memory as a UTF-8 string. */
  readString(ptr: number, len: number): string {
    if (ptr === 0 || len <= 0) return "";
    return decoder.decode(new Uint8Array(this.wasmMemory.buffer, ptr, len));
  }

  /**
   * Allocate a buffer, call fn(ptr, len), free the buffer, return the result.
   * Frees the buffer even if fn throws.
   */
  withString<T>(str: string, fn: (ptr: number, len: number) => T): T {
    const { ptr, len } = this.writeString(str);
    try {
      return fn(ptr, len);
    } finally {
      this.free(ptr);
    }
  }

  /**
   * Allocate two buffers, call fn(ptr1, len1, ptr2, len2), free both.
   */
  withStrings<T>(
    a: string,
    b: string,
    fn: (aPtr: number, aLen: number, bPtr: number, bLen: number) => T,
  ): T {
    const { ptr: aPtr, len: aLen } = this.writeString(a);
    try {
      const { ptr: bPtr, len: bLen } = this.writeString(b);
      try {
        return fn(aPtr, aLen, bPtr, bLen);
      } finally {
        this.free(bPtr);
      }
    } finally {
      this.free(aPtr);
    }
  }

  /**
   * Read a Go-written string from a caller-supplied buffer of `capacity` bytes.
   * Passes outPtr and capacity to fn; fn returns the actual byte count written
   * (or -1 meaning "null/absent"). Returns the string, or null if fn returned -1.
   */
  readOut(
    capacity: number,
    fn: (outPtr: number, maxLen: number) => number,
  ): string | null {
    const ptr = this.alloc(capacity);
    try {
      const written = fn(ptr, capacity);
      if (written < 0) return null;
      return this.readString(ptr, written);
    } finally {
      this.free(ptr);
    }
  }

  /**
   * Write raw bytes into WASM memory and call fn(ptr, len).
   */
  withBytes<T>(data: Uint8Array, fn: (ptr: number, len: number) => T): T {
    if (data.length === 0) return fn(0, 0);
    const ptr = this.alloc(data.length);
    try {
      new Uint8Array(this.wasmMemory.buffer, ptr, data.length).set(data);
      return fn(ptr, data.length);
    } finally {
      this.free(ptr);
    }
  }
}
