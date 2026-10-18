export interface JsonLeaf {
  /** Key-name path only (array indices omitted), for field classification. */
  pathSegments: string[];
  fieldName: string;
  /** Decoded string value, or exact number token text. */
  raw: string;
  span: { start: number; end: number };
  valueKind: "string" | "number";
}

/** Collect string/number leaves from JSON source (duplicate keys, \\uXXXX). */
export function collectJsonLeaves(
  source: string,
  _parsed: unknown,
  from = 0,
): JsonLeaf[] {
  const leaves: JsonLeaf[] = [];
  let i = skipWs(source, from);
  if (source.charCodeAt(i) === 123 /* { */) {
    scanObject(source, i, [], leaves);
  } else if (source.charCodeAt(i) === 91 /* [ */) {
    scanArray(source, i, [], "", leaves);
  }
  return leaves;
}

export function parseJsonDocument(
  input: string,
  format: "json" | "jsonl",
):
  | { ok: true; documents: Array<{ value: unknown; from: number }> }
  | { ok: false; error: string } {
  if (format === "json") {
    try {
      return {
        ok: true,
        documents: [{ value: JSON.parse(input) as unknown, from: 0 }],
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : "invalid JSON",
      };
    }
  }

  const documents: Array<{ value: unknown; from: number }> = [];
  let offset = 0;
  const lines = input.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    if (line === undefined) continue;
    const trimmed = line.trim();
    if (!trimmed) {
      offset += line.length + 1;
      continue;
    }
    const leading = line.indexOf(trimmed[0]!);
    const from = offset + Math.max(leading, 0);
    try {
      documents.push({ value: JSON.parse(trimmed) as unknown, from });
    } catch (error) {
      return {
        ok: false,
        error: `invalid JSONL at line ${lineIndex + 1}: ${
          error instanceof Error ? error.message : "parse error"
        }`,
      };
    }
    offset += line.length + 1;
  }
  return { ok: true, documents };
}

function scanObject(
  source: string,
  start: number,
  pathSegments: string[],
  leaves: JsonLeaf[],
): number {
  let i = start + 1; // after {
  i = skipWs(source, i);
  if (source.charCodeAt(i) === 125 /* } */) return i + 1;

  while (i < source.length) {
    i = skipWs(source, i);
    const keyTok = readJsonStringToken(source, i);
    if (!keyTok) return i;
    const key = keyTok.decoded;
    i = skipWs(source, keyTok.end);
    if (source.charCodeAt(i) !== 58 /* : */) return i;
    i = skipWs(source, i + 1);
    i = scanValue(source, i, [...pathSegments, key], key, leaves);
    i = skipWs(source, i);
    if (source.charCodeAt(i) === 44 /* , */) {
      i += 1;
      continue;
    }
    if (source.charCodeAt(i) === 125 /* } */) return i + 1;
    return i;
  }
  return i;
}

function scanArray(
  source: string,
  start: number,
  pathSegments: string[],
  fieldName: string,
  leaves: JsonLeaf[],
): number {
  let i = start + 1; // after [
  i = skipWs(source, i);
  if (source.charCodeAt(i) === 93 /* ] */) return i + 1;

  while (i < source.length) {
    i = skipWs(source, i);
    // Array elements inherit parent field name / path (no index in path).
    i = scanValue(source, i, pathSegments, fieldName, leaves);
    i = skipWs(source, i);
    if (source.charCodeAt(i) === 44 /* , */) {
      i += 1;
      continue;
    }
    if (source.charCodeAt(i) === 93 /* ] */) return i + 1;
    return i;
  }
  return i;
}

function scanValue(
  source: string,
  start: number,
  pathSegments: string[],
  fieldName: string,
  leaves: JsonLeaf[],
): number {
  const c = source.charCodeAt(start);
  if (c === 123 /* { */) {
    return scanObject(source, start, pathSegments, leaves);
  }
  if (c === 91 /* [ */) {
    return scanArray(source, start, pathSegments, fieldName, leaves);
  }
  if (c === 34 /* " */) {
    const tok = readJsonStringToken(source, start);
    if (!tok) return start + 1;
    leaves.push({
      pathSegments,
      fieldName,
      raw: tok.decoded,
      span: { start: start + 1, end: tok.end - 1 },
      valueKind: "string",
    });
    return tok.end;
  }
  if (c === 45 /* - */ || (c >= 48 && c <= 57)) {
    const end = readJsonNumberEnd(source, start);
    if (end !== null) {
      leaves.push({
        pathSegments,
        fieldName,
        raw: source.slice(start, end),
        span: { start, end },
        valueKind: "number",
      });
      return end;
    }
  }
  // true / false / null - skip literal
  if (source.startsWith("true", start)) return start + 4;
  if (source.startsWith("false", start)) return start + 5;
  if (source.startsWith("null", start)) return start + 4;
  return start + 1;
}

function skipWs(source: string, start: number): number {
  let i = start;
  while (i < source.length) {
    const c = source.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13) i += 1;
    else break;
  }
  return i;
}

/** Read `"…"` starting at the opening quote; returns end past the closing quote. */
function readJsonStringToken(
  source: string,
  start: number,
): { end: number; decoded: string } | null {
  if (source.charCodeAt(start) !== 34) return null;
  let i = start + 1;
  let decoded = "";
  while (i < source.length) {
    const c = source.charCodeAt(i);
    if (c === 34 /* " */) {
      return { end: i + 1, decoded };
    }
    if (c === 92 /* \ */) {
      if (i + 1 >= source.length) return null;
      const m = source.charCodeAt(i + 1);
      if (m === 117 /* u */ && i + 5 < source.length) {
        const hex = source.slice(i + 2, i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) return null;
        decoded += String.fromCharCode(Number.parseInt(hex, 16));
        i += 6;
        continue;
      }
      const map: Record<number, string> = {
        34: '"',
        92: "\\",
        47: "/",
        98: "\b",
        102: "\f",
        110: "\n",
        114: "\r",
        116: "\t",
      };
      const ch = map[m];
      if (ch === undefined) return null;
      decoded += ch;
      i += 2;
      continue;
    }
    if (c === 10 || c === 13) return null;
    decoded += source[i]!;
    i += 1;
  }
  return null;
}

function readJsonNumberEnd(source: string, start: number): number | null {
  let i = start;
  if (source.charCodeAt(i) === 45 || source.charCodeAt(i) === 43) i += 1;
  if (i >= source.length) return null;

  let sawDigit = false;
  while (i < source.length && isDigit(source.charCodeAt(i))) {
    sawDigit = true;
    i += 1;
  }
  if (source.charCodeAt(i) === 46 /* . */) {
    i += 1;
    while (i < source.length && isDigit(source.charCodeAt(i))) {
      sawDigit = true;
      i += 1;
    }
  }
  const exp = source.charCodeAt(i);
  if (exp === 101 /* e */ || exp === 69 /* E */) {
    i += 1;
    const sign = source.charCodeAt(i);
    if (sign === 43 || sign === 45) i += 1;
    let expDigits = false;
    while (i < source.length && isDigit(source.charCodeAt(i))) {
      expDigits = true;
      i += 1;
    }
    if (!expDigits) return null;
  }
  return sawDigit ? i : null;
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}
