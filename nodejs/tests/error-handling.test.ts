// Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Waf } from "../src/waf.js";
import { _resetForTest } from "../src/loader.js";

let waf: Waf;

beforeAll(async () => {
  waf = await Waf.create({ rules: ["SecRuleEngine On"] });
});

afterAll(() => {
  waf.free();
  _resetForTest();
});

describe("WAF creation errors", () => {
  it("throws on invalid SecLang directive", async () => {
    await expect(
      Waf.create({ rules: ["SecRule INVALID_VARIABLE @rx .* id:999,phase:99"] }),
    ).rejects.toThrow();
  });

  it("succeeds with valid directives", async () => {
    const w = await Waf.create({
      rules: [`SecRuleEngine DetectionOnly`],
    });
    expect(w.rulesCount).toBeGreaterThanOrEqual(0);
    w.free();
  });
});

describe("WAF lifecycle", () => {
  it("rulesCount reflects loaded rules", async () => {
    const w = await Waf.create({
      rules: [
        `SecRuleEngine On
SecRule ARGS "@rx test" "id:600,phase:1,deny"
SecRule ARGS "@rx test2" "id:601,phase:2,deny"`,
      ],
    });
    try {
      expect(w.rulesCount).toBe(2);
    } finally {
      w.free();
    }
  });

  it("double-free of a WAF is a no-op", () => {
    const w = waf;
    // We can't double-free the shared waf here; test with a separate instance
    Waf.create({ rules: ["SecRuleEngine On"] }).then((w2) => {
      w2.free();
      expect(() => w2.free()).not.toThrow();
    });
  });

  it("newTransaction after free throws", async () => {
    const w = await Waf.create({ rules: ["SecRuleEngine On"] });
    w.free();
    expect(() => w.newTransaction()).toThrow(/freed/);
  });
});

describe("transaction input validation", () => {
  it("handles empty body writes", () => {
    const tx = waf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 1, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      expect(tx.processRequestHeaders()).toBeNull();
      // empty body should not throw or return intervention
      expect(tx.appendRequestBody(new Uint8Array(0))).toBeNull();
      expect(tx.appendRequestBody("")).toBeNull();
      expect(tx.processRequestBody()).toBeNull();
    } finally {
      tx.free();
    }
  });

  it("handles unicode in headers and URI", () => {
    const tx = waf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 2, "10.0.0.1", 80);
      tx.processUri("/path/🚀?q=héllo", "GET", "HTTP/2.0");
      tx.addRequestHeader("X-Custom", "héllo wörld");
      expect(() => tx.processRequestHeaders()).not.toThrow();
    } finally {
      tx.free();
    }
  });

  it("handles very long header values", () => {
    const tx = waf.newTransaction();
    try {
      const longVal = "A".repeat(8192);
      tx.processConnection("1.2.3.4", 3, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("X-Long", longVal);
      expect(() => tx.processRequestHeaders()).not.toThrow();
    } finally {
      tx.free();
    }
  });

  it("handles multiple transactions from the same WAF concurrently", async () => {
    const txs = Array.from({ length: 10 }, () => waf.newTransaction());
    try {
      for (const tx of txs) {
        tx.processConnection("1.2.3.4", 99, "10.0.0.1", 80);
        tx.processUri("/", "GET", "HTTP/1.1");
        expect(tx.processRequestHeaders()).toBeNull();
      }
    } finally {
      for (const tx of txs) tx.free();
    }
  });

  it("updateStatusCode does not throw", () => {
    const tx = waf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 4, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      tx.processRequestHeaders();
      tx.processRequestBody();
      tx.processResponseHeaders(200, "HTTP/1.1");
      tx.processResponseBody();
      expect(() => tx.updateStatusCode(200)).not.toThrow();
    } finally {
      tx.free();
    }
  });
});

describe("Symbol.dispose support", () => {
  it("transaction is freed via using declaration", () => {
    let freed = false;
    const tx = waf.newTransaction();
    const origFree = tx.free.bind(tx);
    // Monkey-patch free to detect it was called
    (tx as unknown as Record<string, unknown>)["free"] = () => {
      freed = true;
      origFree();
    };
    {
      // Simulate: using tx = ...
      tx[Symbol.dispose]();
    }
    expect(freed).toBe(true);
  });
});
