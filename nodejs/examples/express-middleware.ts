// Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Express WAF middleware example.
//
// Usage:
//   const waf = await Waf.create({ rules: [...] });
//   app.use(corazaMiddleware(waf));

import type { RequestHandler, Request, Response, NextFunction } from "express";
import type { Waf } from "../src/waf.js";

/**
 * Create an Express middleware that runs every request through Coraza.
 *
 * Phases covered: connection, URI, request headers, request body.
 * The request body is buffered internally; downstream handlers receive it
 * via `req.rawBody` (a Buffer) rather than through a streaming parser.
 *
 * @param waf - A pre-initialised Waf instance. The caller owns its lifecycle.
 */
export function corazaMiddleware(waf: Waf): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const tx = waf.newTransaction();

    // ── Phase 1: connection ────────────────────────────────────────────────
    const clientIp =
      (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim() ??
      req.socket.remoteAddress ??
      "127.0.0.1";
    const serverIp = req.socket.localAddress ?? "127.0.0.1";
    const serverPort = req.socket.localPort ?? 80;
    tx.processConnection(clientIp, 0, serverIp, serverPort);

    // ── Phase 1: URI ───────────────────────────────────────────────────────
    tx.processUri(
      req.originalUrl,
      req.method,
      `HTTP/${req.httpVersion}`,
    );

    // ── Phase 1: request headers ───────────────────────────────────────────
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined) {
        tx.addRequestHeader(
          name,
          Array.isArray(value) ? value.join(", ") : value,
        );
      }
    }

    const headersIt = tx.processRequestHeaders();
    if (headersIt) {
      const status = headersIt.status;
      headersIt.free();
      tx.processLogging();
      tx.free();
      res.status(status).set("Content-Type", "text/plain").send("Blocked by WAF");
      return;
    }

    // ── Phase 2: request body ──────────────────────────────────────────────
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      // Attach buffered body for downstream handlers
      (req as Request & { rawBody: Buffer }).rawBody = body;

      let bodyIt = body.length > 0 ? tx.appendRequestBody(body) : null;
      bodyIt ??= tx.processRequestBody();

      if (bodyIt) {
        const status = bodyIt.status;
        bodyIt.free();
        tx.processLogging();
        tx.free();
        res.status(status).set("Content-Type", "text/plain").send("Blocked by WAF");
        return;
      }

      // ── Logging on response finish ───────────────────────────────────────
      res.on("finish", () => {
        tx.processLogging();
        tx.free();
      });

      next();
    });
  };
}
