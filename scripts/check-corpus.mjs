#!/usr/bin/env node
// Compare redactor output to expectations.json (and links.json if present).
// Usage: node scripts/check-corpus.mjs <origDir> <outDir> [--verbose]
// Output files must keep the same names as the originals.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { expandSecrets } from "./corpus-secrets.mjs";

const [origDir, outDir, ...flags] = process.argv.slice(2);
if (!origDir || !outDir) {
  console.error("Usage: node scripts/check-corpus.mjs <origDir> <outDir> [--verbose]");
  process.exit(2);
}
const verbose = flags.includes("--verbose");
const expectations = JSON.parse(expandSecrets(readFileSync(join(origDir, "expectations.json"), "utf8")));
const lines = (dir, name) => expandSecrets(readFileSync(join(dir, name), "utf8")).split("\n").slice(0, -1);

const LABEL = { R: "LEAK", S: "SECRET LEAK", K: "ALTERED" };
const NOM = /^[A-ZÀ-ÝŽ][\p{L}'’-]+(?:[ ,]+[A-ZÀ-ÝŽ][\p{L}'’-]+)+$/u;
const TITRES = new Set(["mme", "mlle", "monsieur", "madame", "docteur", "prestataire"]);
const escWord = (w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const stats = {};
const problems = [];
const review = [];
const fileErrors = [];
const cache = new Map();

for (const name of new Set(expectations.map((e) => e.file))) {
  const outPath = join(outDir, name);
  if (!existsSync(outPath)) {
    fileErrors.push(`${name}: missing output file`);
    continue;
  }
  const orig = lines(origDir, name);
  const out = lines(outDir, name);
  cache.set(name, { orig, out });
  if (orig.length !== out.length) {
    fileErrors.push(`${name}: ${orig.length} input lines, ${out.length} output lines (line numbers no longer match)`);
  }
  if (name.endsWith(".ndjson")) {
    out.forEach((l, i) => {
      try {
        JSON.parse(l);
      } catch (err) {
        fileErrors.push(`${name}:${i + 1}: output is no longer valid JSON (${err.message})`);
      }
    });
  }
}

for (const e of expectations) {
  const entry = cache.get(e.file);
  if (!entry) continue;
  const outLine = entry.out[e.line - 1];
  const s = (stats[e.file] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 });
  s[e.cat]++;
  if (outLine === undefined) {
    s.bad++;
    problems.push({ ...e, kind: "MISSING LINE", outLine: "" });
    continue;
  }
  const present = outLine.includes(e.text);
  if (e.cat === "K" && !present) {
    s.bad++;
    problems.push({ ...e, kind: LABEL.K, outLine });
  } else if ((e.cat === "R" || e.cat === "S") && present) {
    s.bad++;
    problems.push({ ...e, kind: LABEL[e.cat], outLine });
  } else if (e.cat === "D") {
    review.push({ ...e, present, outLine });
  }
  // Same value, different case still counts as a leak.
  if ((e.cat === "R" || e.cat === "S") && !present && e.text.length >= 5 && /[A-Za-z]/.test(e.text) && outLine.toLowerCase().includes(e.text.toLowerCase())) {
    const kTxt = expectations.filter((k) => k.file === e.file && k.line === e.line && k.cat === "K").map((k) => k.text.toLowerCase()).join(" ");
    if (!kTxt.includes(e.text.toLowerCase())) {
      s.bad++;
      problems.push({ ...e, kind: LABEL[e.cat], outLine, note: `value still present with different case (${e.note})` });
    }
  }
  // Multi-word names: no token may remain (partial replace leaks the surname).
  if (e.cat === "R" && NOM.test(e.text)) {
    const kTexts = expectations.filter((k) => k.file === e.file && k.line === e.line && k.cat === "K").map((k) => k.text.toLowerCase()).join(" ");
    for (const w of e.text.match(/[\p{L}\p{N}'’-]{3,}/gu) ?? []) {
      if (TITRES.has(w.toLowerCase()) || kTexts.includes(w.toLowerCase())) continue;
      if (new RegExp("(?<![\\p{L}\\p{N}])" + escWord(w) + "(?![\\p{L}\\p{N}])", "iu").test(outLine)) {
        s.bad++;
        problems.push({ ...e, kind: LABEL.R, outLine, note: `partial replace: "${w}" still present (${e.note})` });
        break;
      }
    }
  }
  // Labeled values: only the value must disappear, not the key.
  if ((e.cat === "R" || e.cat === "S") && !present && !e.noLabel) {
    // e.noLabel: `=` is part of the secret value, not a field separator.
    const km = /^"?([A-Za-z_][\w.\-]{2,})"?[=:]\s*(?=\S)/.exec(e.text);
    const origLine = entry.orig[e.line - 1] ?? "";
    if (km && !/^[0-9a-fA-F:]+$/.test(e.text) && origLine.split(km[1]).length > outLine.split(km[1]).length) {
      s.bad++;
      problems.push({ ...e, kind: LABEL.K, outLine, note: `label "${km[1]}" destroyed: only the value should change (${e.note})` });
    }
  }
}

// Invariant: one alias must not map to two original IPv4s, and vice versa.
const IPV4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;
for (const [name, { orig, out }] of cache) {
  const forward = new Map();
  const backward = new Map();
  orig.forEach((line, i) => {
    const a = line.match(IPV4) ?? [];
    const b = (out[i] ?? "").match(IPV4) ?? [];
    if (a.length !== b.length) return;
    a.forEach((ip, k) => {
      const alias = b[k];
      if (ip === alias) return;
      (forward.get(ip) ?? forward.set(ip, new Set()).get(ip)).add(alias);
      (backward.get(alias) ?? backward.set(alias, new Set()).get(alias)).add(ip);
    });
  });
  for (const [alias, origins] of backward) {
    if (origins.size > 1) {
      problems.push({ file: name, line: 0, text: alias, kind: "COLLISION", note: `alias shared by several original IPs: ${[...origins].join(", ")}` });
      (stats[name] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 }).bad++;
    }
  }
  for (const [ip, aliases] of forward) {
    if (aliases.size > 1) {
      problems.push({ file: name, line: 0, text: ip, kind: "INCOHERENT", note: `same IP has several aliases: ${[...aliases].join(", ")}` });
      (stats[name] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 }).bad++;
    }
  }
}

// Invariant: sentinel "-" must never be replaced or propagated.
const DASH_A = /(?:^|[\s"=,:])-(?=$|[\s",])/g;
const DASH_B = /\\t-(?=\\r)/g;
const dashes = (l) => (l.match(DASH_A) ?? []).length + (l.match(DASH_B) ?? []).length;
for (const [name, { orig, out }] of cache) {
  orig.forEach((line, i) => {
    const a = dashes(line);
    const b = dashes(out[i] ?? "");
    if (b < a) {
      problems.push({ file: name, line: i + 1, text: "-", kind: "SENTINEL", note: `${a - b} sentinel "-" replaced (${a} in, ${b} out)` });
      (stats[name] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 }).bad++;
    }
  });
}

// Invariant: timestamps and log levels are not PII (catch unlisted K false positives).
const COLLAT = [
  ["timestamp", /(?<![\d:])\d{1,2}:\d{2}:\d{2}(?:[.,]\d{1,9}(?![\d.]))?(?![\d:])/g],
  ["log level", /\b(?:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRITICAL|FATAL|SEVERE)\b/g],
];
for (const [name, { orig, out }] of cache) {
  if (orig.length !== out.length) continue;
  orig.forEach((line, i) => {
    // Times/dates that are the expected secret on this line (password=12:30:45).
    const secretTexts = new Set(
      expectations
        .filter((e) => e.file === name && e.line === i + 1 && (e.cat === "S" || e.cat === "R"))
        .map((e) => e.text),
    );
    for (const [what, rx] of COLLAT) {
      const lost = [];
      const seen = new Set();
      for (const m of line.match(rx) ?? []) {
        if (seen.has(m)) continue;
        seen.add(m);
        if ([...secretTexts].some((t) => t === m || t.includes(m))) continue;
        const a = line.split(m).length - 1;
        const b = (out[i] ?? "").split(m).length - 1;
        if (b < a) lost.push(m);
      }
      if (lost.length) {
        problems.push({ file: name, line: i + 1, text: lost.join(" "), kind: "COLLATERAL", note: `${what} destroyed: ${lost.join(", ")} (not personal data)` });
        (stats[name] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 }).bad++;
      }
    }
  });
}

// Structure invariants: file format must survive redaction.
const kindOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);
const skeleton = (v, path, out) => {
  out.set(path, kindOf(v));
  if (Array.isArray(v)) v.forEach((x, i) => skeleton(x, `${path}[${i}]`, out));
  else if (v && typeof v === "object") for (const k of Object.keys(v)) skeleton(v[k], `${path}.${k}`, out);
  return out;
};
const diffSkeleton = (a, b) => {
  const A = skeleton(a, "$", new Map());
  const B = skeleton(b, "$", new Map());
  for (const [k, ta] of A) {
    if (!B.has(k)) return `missing key or element: ${k}`;
    const tb = B.get(k);
    if (ta !== tb && !(ta === "number" && tb === "null")) return `type changed at ${k}: ${ta} → ${tb}`;
  }
  for (const k of B.keys()) if (!A.has(k)) return `added key: ${k}`;
  return null;
};
const csvFields = (line, d) => {
  let n = 1, q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { if (q && line[i + 1] === '"') i++; else q = !q; }
    else if (c === d && !q) n++;
  }
  return n;
};
const xmlTags = (l) => (l.match(/<\/?[A-Za-z_][^\s>\/]*|<!\[CDATA\[|\]\]>/g) ?? []).join("");
const structBad = (name, line, note) => {
  problems.push({ file: name, line, text: "", kind: "STRUCTURE", note });
  (stats[name] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 }).bad++;
};
for (const [name, { orig, out }] of cache) {
  if (orig.length !== out.length) continue;
  if (name.endsWith(".json")) {
    try { const d = diffSkeleton(JSON.parse(orig.join("\n")), JSON.parse(out.join("\n"))); if (d) structBad(name, 0, `JSON document: ${d}`); }
    catch (err) { structBad(name, 0, `document is no longer valid JSON (${err.message})`); }
  }
  const delim = name.endsWith(".csv") ? [";", ",", "\t"].map((d) => [d, (orig[0] ?? "").split(d).length]).sort((a, b) => b[1] - a[1])[0][0] : null;
  const isXml = /xml/i.test(name);
  orig.forEach((line, i) => {
    const o = out[i] ?? "";
    if (name.endsWith(".ndjson") && line.trim()) {
      try { const d = diffSkeleton(JSON.parse(line), JSON.parse(o)); if (d) structBad(name, i + 1, `JSON structure: ${d}`); } catch { /* already reported above */ }
    }
    const t1 = (line.match(/\t/g) ?? []).length, t2 = (o.match(/\t/g) ?? []).length;
    if (t1 !== t2) structBad(name, i + 1, `tabs: ${t1} in, ${t2} out (columns shifted)`);
    if (delim && csvFields(line, delim) !== csvFields(o, delim)) structBad(name, i + 1, `CSV: ${csvFields(line, delim)} fields in, ${csvFields(o, delim)} out (separator "${delim}")`);
    for (const [a, b, nom] of [["[", "]", "brackets"], ["(", ")", "parentheses"]]) {
      const cnt = (x, c) => x.split(c).length - 1;
      if (cnt(line, a) === cnt(line, b) && cnt(o, a) !== cnt(o, b)) structBad(name, i + 1, `unbalanced ${nom} in output (balanced in input): an alias ate a delimiter`);
    }
    if (isXml && xmlTags(line) !== xmlTags(o)) structBad(name, i + 1, "XML: tag sequence changed (document would no longer be equivalent)");
  });
}

// links.json: SAME entity → same alias; DIFF entities → different aliases.
// Values are located via left/right context that must survive redaction.
const linksPath = join(origDir, "links.json");
const links = existsSync(linksPath) ? JSON.parse(expandSecrets(readFileSync(linksPath, "utf8"))) : [];
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const normalise = (v, mode) => {
  let x = v.toLowerCase();
  if (mode === "v6") x = x.replace(/^::ffff:/, "");
  if (mode === "host") x = x.replace(/\$$/, "").split(".")[0];
  return x;
};
for (const l of links) {
  const got = [];
  for (const it of l.items) {
    const entry = cache.get(it.file);
    if (!entry) continue;
    const outLine = entry.out[it.line - 1] ?? "";
    const afters = it.outAfter ?? [it.after];
    const right = afters.map((x) => escRe(x)).join("|");
    const m = new RegExp((it.outBeforeRe ?? escRe(it.before)) + "(.*?)(?:" + right + ")" + (afters.every((x) => x === "") ? "$" : "")).exec(outLine);
    got.push({ it, alias: m ? m[1] : null });
  }
  if (!got.length) continue;
  const stat = (stats[got[0].it.file] ??= { R: 0, S: 0, K: 0, D: 0, bad: 0 });
  const missing = got.filter((g) => g.alias === null);
  const show = got.map((g) => `${g.it.file.slice(0, 2)}:${g.it.line}=${g.alias === null ? "?" : JSON.stringify(g.alias)}`).join("  ");
  if (missing.length) {
    problems.push({ file: got[0].it.file, line: got[0].it.line, text: got[0].it.value, kind: "LINK ?", note: `context not found in output (line changed too much) - ${show}` });
    stat.bad++;
    continue;
  }
  const norm = got.map((g) => normalise(g.alias, l.norm));
  const distinct = new Set(norm).size;
  const unchanged = got.some((g) => normalise(g.it.value, l.norm) === normalise(g.alias, l.norm));
  if (l.kind === "SAME" && distinct > 1) {
    problems.push({ file: got[0].it.file, line: got[0].it.line, text: got[0].it.value, kind: "LINK", note: `${l.note} → ${show}` });
    stat.bad++;
  } else if (l.kind === "DIFF" && distinct < got.length) {
    problems.push({ file: got[0].it.file, line: got[0].it.line, text: got[0].it.value, kind: "LINK", note: `${l.note} → ${show}` });
    stat.bad++;
  } else if (unchanged) {
    // Clear-text but consistent: already reported by R expectations; skip duplicate.
  }
}

const isInv = (p) => /^(COLLISION|INCOHERENT|SENTINEL|COLLATERAL|LINK|STRUCTURE)/.test(p.kind);
const clip = (s, n = 140) => (s.length > n ? s.slice(0, n) + "…" : s);

for (const msg of fileErrors) console.log(`\x1b[31m✗\x1b[0m ${msg}`);
if (fileErrors.length) console.log();

console.log("Problems (must fix):");
if (!problems.length) console.log("  none");
for (const p of problems) {
  console.log(`  [${p.kind}] ${p.file}:${p.line}  ${JSON.stringify(clip(p.text, 60))}  - ${p.note}`);
}

console.log("\nTo review (design decisions):", review.length, verbose ? "" : "(--verbose for detail)");
if (verbose) {
  for (const r of review) {
    console.log(`  ${r.file}:${r.line}  ${JSON.stringify(clip(r.text, 60))}  → ${r.present ? "kept" : "changed"}  - ${r.note}`);
  }
}

console.log("\nSummary by file:");
let totalBad = 0;
for (const [name, s] of Object.entries(stats)) {
  const collisions = problems.filter((p) => p.file === name && isInv(p)).length;
  const checked = s.R + s.S + s.K;
  totalBad += s.bad;
  console.log(`  ${name.padEnd(28)} ${String(checked - (s.bad - collisions)).padStart(3)}/${String(checked).padEnd(3)} ok   (leaks ${problems.filter((p) => p.file === name && (p.kind === "LEAK" || p.kind === "SECRET LEAK")).length}, invariants ${problems.filter((p) => p.file === name && isInv(p)).length}, false positives ${problems.filter((p) => p.file === name && p.kind === LABEL.K).length}, to review ${s.D})`);
}
process.exit(totalBad || fileErrors.length ? 1 : 0);
