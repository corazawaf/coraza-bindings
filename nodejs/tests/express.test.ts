// Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end tests: Coraza middleware in an Express application.
//
// Each test suite spins up a real Express app with the WAF middleware
// and makes HTTP requests via supertest (no port binding needed).

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express, { type Request, type Response } from "express";
import supertest from "supertest";
import { Waf } from "../src/waf.js";
import { corazaMiddleware } from "../examples/express-middleware.js";
import { _resetForTest } from "../src/loader.js";

// ── Shared WAF + app ────────────────────────────────────────────────────────

const RULES = `
SecRuleEngine On

# Block XSS in any parsed argument
SecRule ARGS "@rx <script" \
  "id:1001,phase:2,deny,status:403,msg:'XSS attempt'"

# Block SQL injection in URI
SecRule REQUEST_URI "@rx (?i)union.*select" \
  "id:1002,phase:1,deny,status:403,msg:'SQLi in URI'"

# Block a specific header value
SecRule REQUEST_HEADERS:X-Evil "@streq 1" \
  "id:1003,phase:1,deny,status:403,msg:'Evil header'"

# Block a specific GET argument
SecRule ARGS_GET:hack "@streq yes" \
  "id:1004,phase:1,deny,status:403,msg:'Hack arg'"
`;

let waf: Waf;
let request: ReturnType<typeof supertest>;

beforeAll(async () => {
  waf = await Waf.create({ rules: [RULES] });

  const app = express();
  app.use(corazaMiddleware(waf));

  // Echo handler — reaches here only when the WAF passes the request
  app.all("/{*path}", (req: Request & { rawBody?: Buffer }, res: Response) => {
    res.status(200).json({
      ok: true,
      method: req.method,
      url: req.originalUrl,
      body: req.rawBody?.toString() ?? "",
    });
  });

  request = supertest(app);
});

afterAll(() => {
  waf.free();
  _resetForTest();
});

// ── Clean requests pass through ─────────────────────────────────────────────

describe("clean requests pass through", () => {
  it("GET / → 200", async () => {
    const res = await request.get("/");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("GET with benign query string → 200", async () => {
    const res = await request.get("/search?q=hello+world");
    expect(res.status).toBe(200);
  });

  it("POST with clean JSON body → 200", async () => {
    const res = await request
      .post("/api/data")
      .set("Content-Type", "application/json")
      .send(JSON.stringify({ name: "Alice", age: 30 }));
    expect(res.status).toBe(200);
    expect(res.body.body).toContain("Alice");
  });

  it("POST with clean form body → 200", async () => {
    const res = await request
      .post("/submit")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("username=alice&password=hunter2");
    expect(res.status).toBe(200);
  });

  it("sends response body back", async () => {
    const res = await request.get("/echo");
    expect(res.body).toMatchObject({ ok: true, method: "GET" });
  });
});

// ── Blocking by URI ─────────────────────────────────────────────────────────

describe("blocking: URI-based rules", () => {
  it("blocks SQL injection in URI → 403", async () => {
    const res = await request.get("/items?id=1+UNION+SELECT+*+FROM+users");
    expect(res.status).toBe(403);
    expect(res.text).toContain("Blocked");
  });

  it("blocks SQLi case-insensitive", async () => {
    const res = await request.get("/items?id=1+union+select+null");
    expect(res.status).toBe(403);
  });
});

// ── Blocking by request header ──────────────────────────────────────────────

describe("blocking: request headers", () => {
  it("blocks request with evil header → 403", async () => {
    const res = await request.get("/").set("X-Evil", "1");
    expect(res.status).toBe(403);
  });

  it("passes request without evil header → 200", async () => {
    const res = await request.get("/").set("X-Evil", "0");
    expect(res.status).toBe(200);
  });
});

// ── Blocking by GET argument ────────────────────────────────────────────────

describe("blocking: GET arguments", () => {
  it("blocks ?hack=yes → 403", async () => {
    const res = await request.get("/?hack=yes");
    expect(res.status).toBe(403);
  });

  it("passes ?hack=no → 200", async () => {
    const res = await request.get("/?hack=no");
    expect(res.status).toBe(200);
  });
});

// ── Blocking by POST body ───────────────────────────────────────────────────

describe("blocking: request body", () => {
  it("blocks XSS in form body → 403", async () => {
    const res = await request
      .post("/comment")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("text=hello+<script>alert(1)</script>");
    expect(res.status).toBe(403);
  });

  it("blocks XSS in second form field → 403", async () => {
    const res = await request
      .post("/api")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("name=alice&comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    expect(res.status).toBe(403);
  });

  it("passes JSON body (ARGS not extracted without JSON processor) → 200", async () => {
    // JSON bodies are NOT automatically parsed into ARGS without SecRequestBodyProcessor JSON.
    // This test documents that behaviour: the raw JSON passes through unblocked.
    const res = await request
      .post("/api")
      .set("Content-Type", "application/json")
      .send(JSON.stringify({ comment: "hello world" }));
    expect(res.status).toBe(200);
  });

  it("passes empty POST body → 200", async () => {
    const res = await request.post("/api");
    expect(res.status).toBe(200);
  });
});

// ── Middleware correctness ──────────────────────────────────────────────────

describe("middleware correctness", () => {
  it("downstream handler receives rawBody", async () => {
    const payload = JSON.stringify({ x: 1 });
    const res = await request
      .post("/echo")
      .set("Content-Type", "application/json")
      .send(payload);
    expect(res.status).toBe(200);
    expect(res.body.body).toBe(payload);
  });

  it("handles concurrent requests without mixing state", async () => {
    // Fire 20 concurrent requests: odd are evil (should be blocked), even are clean
    const tasks = Array.from({ length: 20 }, (_, i) =>
      i % 2 === 0
        ? request.get(`/?q=clean-${i}`)
        : request.get(`/?id=${i}+UNION+SELECT+*+FROM+t`),
    );
    const results = await Promise.all(tasks);
    for (let i = 0; i < results.length; i++) {
      const expected = i % 2 === 0 ? 200 : 403;
      expect(results[i]!.status, `request ${i}`).toBe(expected);
    }
  });

  it("multiple sequential requests reuse the same WAF", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await request.get("/");
      expect(res.status).toBe(200);
    }
  });
});
