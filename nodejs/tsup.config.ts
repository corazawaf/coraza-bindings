import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "node20",
  // Inject __dirname / __filename shims for ESM output so the WASM path works.
  shims: true,
  // Do not bundle node:wasi — it is a Node.js built-in
  external: ["node:wasi", "node:fs", "node:path", "node:url"],
});
