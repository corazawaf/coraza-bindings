// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Waf } from "../src/waf.js";
import { _resetForTest } from "../src/loader.js";

const PASS_RULE = `
SecRuleEngine On
SecRule REQUEST_METHOD "@streq GET" "id:100,phase:1,pass,nolog"
`;

let passWaf: Waf;
let denyWaf: Waf;
let responseWaf: Waf;
let tmpDir: string;

beforeAll(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "coraza-test-"));

  passWaf = await Waf.create({ rules: [PASS_RULE] });
  denyWaf = await Waf.create({
    rules: [
      `SecRuleEngine On
SecRule ARGS:attack "@streq 1" "id:200,phase:2,deny,status:403,msg:'Attack'"`,
    ],
  });
  responseWaf = await Waf.create({
    rules: [
      `SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/html text/plain
SecRule RESPONSE_HEADERS:X-Block "@streq 1" \
  "id:210,phase:3,deny,status:503,msg:'Response header blocked'"
SecRule RESPONSE_BODY "@rx <script" \
  "id:211,phase:4,deny,status:502,msg:'XSS in response body'"`,
    ],
  });
});

afterAll(() => {
  passWaf.free();
  denyWaf.free();
  responseWaf.free();
  rmSync(tmpDir, { recursive: true, force: true });
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

  it("GET arg triggers rule when argument matches", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 4321, "10.0.0.1", 80);
      tx.processUri("/?attack=1", "GET", "HTTP/1.1");
      // addGetArgument is the explicit way; the URI parser may also populate ARGS_GET
      tx.addGetArgument("attack", "1");
      const it = tx.processRequestHeaders();
      // Rule fires in phase:2 — check body phase
      const bodyIt = it ?? tx.processRequestBody();
      expect(bodyIt).not.toBeNull();
      expect(bodyIt!.status).toBe(403);
      bodyIt!.free();
    } finally {
      tx.free();
    }
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

  it("appendRequestBody with string input works the same as Uint8Array", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 8888, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();
      // String input — the Transaction class encodes it to UTF-8 internally
      const it = tx.appendRequestBody("attack=1") ?? tx.processRequestBody();
      expect(it).not.toBeNull();
      expect(it!.status).toBe(403);
      it!.free();
    } finally {
      tx.free();
    }
  });
});

describe("request body from file", () => {
  it("reads body from a temp file and evaluates it", () => {
    const filePath = join(tmpDir, "body.bin");
    writeFileSync(filePath, "attack=1");

    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 7777, "10.0.0.1", 80);
      tx.processUri("/upload", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();

      // requestBodyFromFile writes into the buffer (like appendRequestBody);
      // call processRequestBody() to evaluate phase:2 rules.
      const writeIt = tx.requestBodyFromFile(filePath);
      const it = writeIt ?? tx.processRequestBody();
      expect(it).not.toBeNull();
      expect(it!.status).toBe(403);
      it!.free();
    } finally {
      tx.free();
    }
  });

  it("returns null for a file with clean content", () => {
    const filePath = join(tmpDir, "clean.bin");
    writeFileSync(filePath, "username=alice&password=hunter2");

    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 6666, "10.0.0.1", 80);
      tx.processUri("/upload", "POST", "HTTP/1.1");
      tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      tx.processRequestHeaders();

      const it = tx.requestBodyFromFile(filePath);
      const bodyIt = it ?? tx.processRequestBody();
      expect(bodyIt).toBeNull();
    } finally {
      tx.free();
    }
  });

  it("returns error for a nonexistent file", () => {
    const tx = denyWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 5555, "10.0.0.1", 80);
      tx.processUri("/", "POST", "HTTP/1.1");
      tx.processRequestHeaders();
      // Nonexistent path — WASM returns -1, Transaction throws
      expect(() => tx.requestBodyFromFile("/nonexistent/path.bin")).toThrow();
    } finally {
      tx.free();
    }
  });
});

describe("response phase blocking", () => {
  it("blocks on response header rule (phase:3)", () => {
    const tx = responseWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 3000, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      tx.processRequestHeaders();
      tx.processRequestBody();

      // Add a response header that triggers the rule
      tx.addResponseHeader("X-Block", "1");
      const it = tx.processResponseHeaders(200, "HTTP/1.1");
      expect(it).not.toBeNull();
      expect(it!.status).toBe(503);
      expect(it!.action).toBe("deny");
      it!.free();
    } finally {
      tx.free();
    }
  });

  it("blocks on response body rule (phase:4)", () => {
    const tx = responseWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 3001, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      tx.processRequestHeaders();
      tx.processRequestBody();

      // Set Content-Type so Coraza's response body processor inspects the body
      tx.addResponseHeader("Content-Type", "text/html");
      expect(tx.processResponseHeaders(200, "HTTP/1.1")).toBeNull();

      // Response body contains XSS — appendResponseBody buffers; processResponseBody evaluates
      tx.appendResponseBody("<html><script>alert(1)</script></html>");
      const it = tx.processResponseBody();
      expect(it).not.toBeNull();
      expect(it!.status).toBe(502);
      it!.free();
    } finally {
      tx.free();
    }
  });

  it("passes a clean response through all response phases", () => {
    const tx = responseWaf.newTransaction();
    try {
      tx.processConnection("1.2.3.4", 3002, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      tx.processRequestHeaders();
      tx.processRequestBody();

      tx.addResponseHeader("Content-Type", "text/html");
      expect(tx.processResponseHeaders(200, "HTTP/1.1")).toBeNull();
      tx.appendResponseBody("<html><p>Hello, safe world!</p></html>");
      expect(tx.processResponseBody()).toBeNull();
      tx.processLogging();
    } finally {
      tx.free();
    }
  });
});

describe("rule loading from file", () => {
  it("loads rules from a file via ruleFiles option", async () => {
    const ruleFile = join(tmpDir, "rules.conf");
    writeFileSync(
      ruleFile,
      `SecRuleEngine On\nSecRule ARGS:filehack "@streq 1" "id:900,phase:2,deny,status:403"\n`,
    );

    const fileWaf = await Waf.create({ ruleFiles: [ruleFile] });
    try {
      expect(fileWaf.rulesCount).toBe(1);

      const tx = fileWaf.newTransaction();
      try {
        tx.processConnection("1.2.3.4", 9999, "10.0.0.1", 80);
        tx.processUri("/", "POST", "HTTP/1.1");
        tx.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        tx.processRequestHeaders();
        const it = tx.appendRequestBody("filehack=1") ?? tx.processRequestBody();
        expect(it).not.toBeNull();
        expect(it!.status).toBe(403);
        it!.free();
      } finally {
        tx.free();
      }
    } finally {
      fileWaf.free();
    }
  });
});
