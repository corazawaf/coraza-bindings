# @corazawaf/coraza — Node.js

[OWASP Coraza WAF](https://coraza.io) for Node.js via WebAssembly.

- **No native compilation** — ships a pre-built `.wasm` inside the package.
- **Node.js 20+** required (WASI experimental).
- Fully typed TypeScript API.
- Coraza/v3 rules (ModSecurity-compatible).

---

## Installation

```bash
npm install @corazawaf/coraza
```

---

## Quick start

```ts
import { Waf } from "@corazawaf/coraza";

// Create a WAF with inline rules
const waf = await Waf.create({
  rules: [
    "SecRuleEngine On",
    `SecRule ARGS "@rx <script>" "id:1,phase:2,deny,status:403,msg:'XSS'"`,
  ],
  onRuleMatch: (log) => console.error("[coraza]", log),
});

// Process a request
const tx = waf.newTransaction();
try {
  tx.processConnection("1.2.3.4", 12345, "10.0.0.1", 80);
  tx.processUri("/search?q=<script>alert(1)</script>", "GET", "HTTP/1.1");
  tx.addRequestHeader("Host", "example.com");

  const it = tx.processRequestHeaders();
  if (it) {
    console.log(`Blocked: ${it.status} ${it.action}`);
    it.free();
    return;
  }

  const bodyIt = tx.processRequestBody();
  if (bodyIt) {
    console.log(`Blocked on body: ${bodyIt.status}`);
    bodyIt.free();
    return;
  }

  tx.processLogging();
} finally {
  tx.free();
}

waf.free();
```

---

## API reference

### `Waf`

```ts
class Waf {
  static async create(opts?: WafOptions): Promise<Waf>
  get rulesCount(): number
  newTransaction(): Transaction
  newTransactionWithId(id: string): Transaction
  free(): void
  [Symbol.dispose](): void
}

interface WafOptions {
  rules?: string[];          // inline SecLang directives
  ruleFiles?: string[];      // paths to rule files (WASI filesystem)
  onRuleMatch?: (log: string) => void;      // fires on rule match
  onDebugLog?: (level: number, msg: string) => void;  // debug events
}
```

The first call to `Waf.create()` compiles the WASM module. Subsequent calls
reuse the compiled module (singleton). All rule parsing and WAF creation is
synchronous within the WASM instance.

### `Transaction`

```ts
class Transaction {
  processConnection(clientIp: string, clientPort: number, serverIp: string, serverPort: number): void
  processUri(uri: string, method: string, httpVersion: string): void
  addRequestHeader(name: string, value: string): void
  addGetArgument(name: string, value: string): void
  processRequestHeaders(): Intervention | null
  appendRequestBody(data: Uint8Array | string): Intervention | null
  processRequestBody(): Intervention | null
  requestBodyFromFile(path: string): Intervention | null
  addResponseHeader(name: string, value: string): void
  processResponseHeaders(status: number, proto: string): Intervention | null
  appendResponseBody(data: Uint8Array | string): Intervention | null
  processResponseBody(): Intervention | null
  updateStatusCode(code: number): void
  processLogging(): void
  intervention(): Intervention | null
  free(): void
  [Symbol.dispose](): void
}
```

Methods that return `Intervention | null` return a non-null value when a rule
interrupts the request. Always call `intervention.free()` after reading the
intervention fields.

### `Intervention`

```ts
interface Intervention {
  readonly status: number;        // HTTP status to return (e.g. 403)
  readonly action: string;        // "deny", "redirect", "pass", …
  readonly data: string | null;   // redirect URL or null
  free(): void;
}
```

---

## Full lifecycle example

```ts
import { Waf } from "@corazawaf/coraza";

async function processRequest(req: {
  clientIp: string;
  uri: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}) {
  const waf = await Waf.create({
    rules: [
      "SecRuleEngine On",
      `SecRule REQUEST_HEADERS:X-Blocked "@rx 1" "id:10,phase:1,deny,status:403"`,
    ],
  });

  const tx = waf.newTransaction();
  try {
    tx.processConnection(req.clientIp, 0, "0.0.0.0", 80);
    tx.processUri(req.uri, req.method, "HTTP/1.1");

    for (const [name, value] of Object.entries(req.headers)) {
      tx.addRequestHeader(name, value);
    }

    const headersIt = tx.processRequestHeaders();
    if (headersIt) {
      const status = headersIt.status;
      headersIt.free();
      return { blocked: true, status };
    }

    if (req.body) {
      const bodyIt = tx.appendRequestBody(req.body) ?? tx.processRequestBody();
      if (bodyIt) {
        const status = bodyIt.status;
        bodyIt.free();
        return { blocked: true, status };
      }
    }

    tx.processLogging();
    return { blocked: false };
  } finally {
    tx.free();
    waf.free();
  }
}
```

---

## Using `Symbol.dispose` (`using` declarations)

```ts
// Requires TypeScript ≥ 5.2 and target ≥ ES2022
const waf = await Waf.create({ rules: ["SecRuleEngine On"] });
{
  using tx = waf.newTransaction();
  tx.processUri("/", "GET", "HTTP/1.1");
  tx.processRequestHeaders();
  tx.processLogging();
  // tx.free() called automatically at end of block
}
waf.free();
```

---

## Express middleware

See [`examples/express-middleware.ts`](examples/express-middleware.ts) for a
complete drop-in Express middleware that:

- Processes connection, URI, request headers, and request body
- Returns a `text/plain 403` response on block (customizable)
- Attaches the buffered body to `req.rawBody` for downstream handlers
- Calls `processLogging()` when the response finishes

```ts
import express from "express";
import { Waf } from "@corazawaf/coraza";
import { corazaMiddleware } from "./examples/express-middleware.js";

const waf = await Waf.create({
  rules: [
    "SecRuleEngine On",
    `SecRule ARGS "@rx <script" "id:1,phase:2,deny,status:403,msg:'XSS'"`,
  ],
  onRuleMatch: (log) => console.error("[coraza]", log),
});

const app = express();
app.use(corazaMiddleware(waf));
app.get("/", (req, res) => res.send("Hello!"));
app.listen(3000);
```

> **Note:** `application/json` bodies are not parsed into `ARGS` by default.
> To inspect JSON fields, add `SecRequestBodyProcessor JSON` to your rules.

---

## Coraza version

The bundled WASM is compiled from `github.com/corazawaf/coraza/v3` at the
version pinned in `coraza_version`. To update, bump that file and rebuild.

```bash
bash scripts/build-wasm.sh   # from repository root
```

---

## License

Apache 2.0 — Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
