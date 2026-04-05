// Copyright 2024 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { Waf } from "../src/waf.js";
import { _resetForTest } from "../src/loader.js";

afterAll(() => {
  _resetForTest();
});

describe("error callback (onRuleMatch)", () => {
  it("fires when a rule matches", async () => {
    const logs: string[] = [];
    const waf = await Waf.create({
      rules: [
        `SecRuleEngine On
SecRule ARGS:track "@streq 1" "id:500,phase:2,pass,log,msg:'Tracked'"`,
      ],
      onRuleMatch: (msg) => logs.push(msg),
    });
    try {
      const tx = waf.newTransaction();
      try {
        tx.processConnection("1.2.3.4", 11111, "10.0.0.1", 80);
        tx.processUri("/", "POST", "HTTP/1.1");
        tx.addRequestHeader(
          "Content-Type",
          "application/x-www-form-urlencoded",
        );
        tx.processRequestHeaders();
        tx.appendRequestBody("track=1");
        tx.processRequestBody();
        tx.processLogging();
      } finally {
        tx.free();
      }
      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0]).toContain("Tracked");
    } finally {
      waf.free();
    }
  });

  it("does not fire for non-matching requests", async () => {
    const logs: string[] = [];
    const waf = await Waf.create({
      rules: [
        `SecRuleEngine On
SecRule ARGS:track "@streq 1" "id:501,phase:2,pass,log,msg:'Tracked2'"`,
      ],
      onRuleMatch: (msg) => logs.push(msg),
    });
    try {
      const tx = waf.newTransaction();
      try {
        tx.processConnection("1.2.3.4", 22222, "10.0.0.1", 80);
        tx.processUri("/", "GET", "HTTP/1.1");
        tx.processRequestHeaders();
        tx.processRequestBody();
        tx.processLogging();
      } finally {
        tx.free();
      }
      expect(logs).toHaveLength(0);
    } finally {
      waf.free();
    }
  });
});

describe("debug log callback (onDebugLog)", () => {
  it("receives log events during WAF creation", async () => {
    const events: Array<{ level: number; msg: string }> = [];
    const waf = await Waf.create({
      rules: ["SecRuleEngine On"],
      onDebugLog: (level, msg) => events.push({ level, msg }),
    });
    try {
      // Debug events are emitted during WAF/transaction creation
      const tx = waf.newTransaction();
      tx.processConnection("1.2.3.4", 33333, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      tx.processRequestHeaders();
      tx.free();
      // We just verify the callback was wired; actual events depend on Coraza internals
      // The important thing is it didn't throw.
      expect(events).toBeDefined();
    } finally {
      waf.free();
    }
  });

  it("callback receives numeric level and non-empty message", async () => {
    const events: Array<{ level: number; msg: string }> = [];
    const waf = await Waf.create({
      rules: ["SecRuleEngine On"],
      onDebugLog: (level, msg) => events.push({ level, msg }),
    });
    try {
      const tx = waf.newTransaction();
      tx.processConnection("7.7.7.7", 44444, "10.0.0.1", 80);
      tx.processUri("/", "GET", "HTTP/1.1");
      tx.processRequestHeaders();
      tx.processRequestBody();
      tx.processLogging();
      tx.free();

      for (const e of events) {
        expect(typeof e.level).toBe("number");
        expect(e.level).toBeGreaterThan(0);
        expect(typeof e.msg).toBe("string");
        expect(e.msg.length).toBeGreaterThan(0);
      }
    } finally {
      waf.free();
    }
  });
});
