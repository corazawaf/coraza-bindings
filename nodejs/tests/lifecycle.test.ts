// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Waf } from "../src/waf.js";
import { _resetForTest } from "../src/loader.js";

const PASS_RULE = `
SecRuleEngine On
SecRule REQUEST_METHOD "@streq GET" "id:100,phase:1,pass,nolog"
`;

let passWaf: Waf;
let denyWaf: Waf;

beforeAll(async () => {
  passWaf = await Waf.create({ rules: [PASS_RULE] });
  denyWaf = await Waf.create({
    rules: [
      `SecRuleEngine On
SecRule ARGS:attack "@streq 1" "id:200,phase:2,deny,status:403,msg:'Attack'"`,
    ],
  });
});

afterAll(() => {
  passWaf.free();
  denyWaf.free();
  _resetForTest();
});

describe("full request/response lifecycle", () => {
  it("passes a benign request through all phases", () => {
    const tx = passWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 12345, "10.0.0.1", 80);
      tx.processUri("/hello?foo=bar", "GET", "HTTP/1.1");
      tx.addRequestHeader("Host", "example.com");
      tx.addGetArgument("foo", "bar");

      expect(tx.processRequestHeaders()).toBeNull();
      expect(tx.appendRequestBody(new Uint8Array(0))).toBeNull();
      expect(tx.processRequestBody()).toBeNull();

      tx.addResponseHeader("Content-Type", "text/plain");
      expect(tx.processResponseHeaders(200, "HTTP/1.1")).toBeNull();
      expect(tx.appendResponseBody("Hello, world!")).toBeNull();
      expect(tx.processResponseBody()).toBeNull();

      tx.processLogging();
      expect(tx.intervention()).toBeNull();
    } finally {
      tx.free();
    }
  });

  it("denies a request when a rule matches", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 9000, "10.0.0.1", 80);
      tx.processUri("/vuln", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      expect(tx.processRequestHeaders()).toBeNull();

      // Trigger the rule in the request body phase
      const body = "attack=1";
      const it = tx.appendRequestBody(body);
      const bodyIt = it ?? tx.processRequestBody();

      expect(bodyIt).not.toBeNull();
      expect(bodyIt!.status).toBe(403);
      expect(bodyIt!.action).toBe("deny");
      bodyIt!.free();
    } finally {
      tx.free();
    }
  });

  it("double-free of a transaction is a no-op", () => {
    const tx = passWaf.newTransaction();
    tx.free();
    expect(() => tx.free()).not.toThrow();
  });

  it("using a transaction after free throws", () => {
    const tx = passWaf.newTransaction();
    tx.free();
    expect(() => tx.processRequestHeaders()).toThrow(/freed/);
  });

  it("transaction IDs are returned in intervention", () => {
    const tx = denyWaf.newTransactionWithId("my-tx-id-1");
    try {
      tx.processConnection("5.5.5.5", 1234, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();
      const body = new TextEncoder().encode("attack=1");
      const it = tx.appendRequestBody(body) ?? tx.processRequestBody();
      expect(it).not.toBeNull();
      it!.free();
    } finally {
      tx.free();
    }
  });
});
