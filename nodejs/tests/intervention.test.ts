// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Waf } from "../src/waf.js";
import { _resetForTest } from "../src/loader.js";

let denyWaf: Waf;
let redirectWaf: Waf;

beforeAll(async () => {
  denyWaf = await Waf.create({
    rules: [
      `SecRuleEngine On
SecRule ARGS:evil "@streq yes" "id:300,phase:2,deny,status:403"`,
    ],
  });
  redirectWaf = await Waf.create({
    rules: [
      `SecRuleEngine On
SecRule ARGS:redirect "@streq yes" "id:301,phase:2,redirect:https://example.com/blocked,status:302"`,
    ],
  });
});

afterAll(() => {
  denyWaf.free();
  redirectWaf.free();
  _resetForTest();
});

describe("intervention: deny", () => {
  it("status is 403 and action is deny", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 1111, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();
      const it = tx.appendRequestBody("evil=yes") ?? tx.processRequestBody();
      expect(it).not.toBeNull();
      expect(it!.status).toBe(403);
      expect(it!.action).toBe("deny");
      expect(it!.data).toBeNull();
      it!.free();
    } finally {
      tx.free();
    }
  });

  it("intervention() returns same values as process* result", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 2222, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();
      tx.appendRequestBody("evil=yes");
      tx.processRequestBody();
      const it = tx.intervention();
      expect(it).not.toBeNull();
      expect(it!.status).toBe(403);
      it!.free();
    } finally {
      tx.free();
    }
  });

  it("free() on an intervention is idempotent", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("9.9.9.9", 9999, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();
      tx.appendRequestBody("evil=yes");
      const it = tx.processRequestBody();
      expect(it).not.toBeNull();
      it!.free();
      expect(() => it!.free()).not.toThrow();
    } finally {
      tx.free();
    }
  });
});

describe("intervention: redirect", () => {
  it("status is 302, action is redirect, data contains URL", () => {
    const tx = redirectWaf.newTransaction();
    try {
      tx.processConnection("2.3.4.5", 3333, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();
      const it = tx.appendRequestBody("redirect=yes") ?? tx.processRequestBody();
      expect(it).not.toBeNull();
      expect(it!.status).toBe(302);
      expect(it!.action).toBe("redirect");
      expect(it!.data).toBe("https://example.com/blocked");
      it!.free();
    } finally {
      tx.free();
    }
  });
});
