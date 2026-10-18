#!/usr/bin/env node
/** Redact corpus files into an output dir (same names). Defaults: tests/corpus → tmp/corpus-out. */
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { redactText, DEFAULT_REDACT_OPTIONS } from "../src/core/index";
import { expandSecrets } from "./corpus-secrets.mjs";

const root = resolve(import.meta.dirname, "..");
const inDir = resolve(root, process.argv[2] ?? "tests/corpus");
const outDir = resolve(root, process.argv[3] ?? "tmp/corpus-out");

const LOG_EXT = /\.(log|ndjson|txt|json|csv|eml|ldif)$/i;
const SKIP = new Set([
  "expectations.json",
  "links.json",
  "README.md",
]);

mkdirSync(outDir, { recursive: true });

const files = readdirSync(inDir)
  .filter((name) => LOG_EXT.test(name) && !SKIP.has(name))
  .sort();

if (files.length === 0) {
  console.error(`No log files in ${inDir}`);
  process.exit(2);
}

console.log(`Corpus: ${inDir}`);
console.log(`Output: ${outDir}`);

for (const name of files) {
  const input = expandSecrets(readFileSync(join(inDir, name), "utf8"));
  const started = performance.now();
  const { apply, verify, analyze } = redactText(input, DEFAULT_REDACT_OPTIONS);
  let output = apply.output;
  // check-corpus.mjs drops a trailing empty split("\n") entry; keep line counts aligned.
  if (input.endsWith("\n") && !output.endsWith("\n")) {
    output += "\n";
  }
  writeFileSync(join(outDir, name), output, "utf8");
  const ms = Math.round(performance.now() - started);
  const leaks = verify.remaining.length;
  console.log(
    `  ${name.padEnd(28)} ${String(analyze.summary.uniqueValues).padStart(4)} values · ${ms} ms${
      leaks ? ` · ⚠ ${leaks} verify leaks` : ""
    }`,
  );
}

console.log("OK");
