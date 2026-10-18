import type { FindingKind, MappingEntry } from "./types";
import { foldCase } from "./fold";
import { isBareDateOrTime, isLogTimestampContext } from "./secretValueGuards";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "./sentinels";

/** Apply mappings in one left-to-right pass over the original input (trie). */
export function applyFast(
  input: string,
  mappings: MappingEntry[],
  needsSpanOnly: (value: string, kind?: FindingKind) => boolean,
  surfaceAlias: (alias: string, original: string) => string,
): string {
  const active = mappings.filter((e) => e.decision === "replace");
  if (active.length === 0) return input;

  // Explicit spans (secrets, short numerics, URL-encoded names, …).
  const spanJobs: Array<{ start: number; end: number; alias: string }> = [];
  for (const e of active) {
    for (const sp of e.spans ?? []) {
      const surface = input.slice(sp.start, sp.end);
      spanJobs.push({
        start: sp.start,
        end: sp.end,
        alias: surfaceAlias(e.alias, surface),
      });
    }
  }

  const found = scanMappedHits(input, active, needsSpanOnly).map((h) => ({
    start: h.start,
    end: h.end,
    alias: surfaceAlias(h.alias, h.search),
  }));

  // Spans win over overlapping global hits.
  const spanSorted = spanJobs.slice().sort((a, b) => a.start - b.start);
  const all: Array<{ start: number; end: number; alias: string }> = spanJobs.slice();
  let si = 0;
  for (const f of found) {
    while (si < spanSorted.length && spanSorted[si]!.end <= f.start) si += 1;
    let clash = false;
    for (let k = si; k < spanSorted.length && spanSorted[k]!.start < f.end; k += 1) {
      clash = true;
      break;
    }
    if (!clash) all.push(f);
  }

  all.sort((a, b) => a.start - b.start || b.end - a.end);
  const parts: string[] = [];
  let pos = 0;
  for (const a of all) {
    if (a.start < pos) continue;
    parts.push(input.slice(pos, a.start), a.alias);
    pos = a.end;
  }
  parts.push(input.slice(pos));
  return parts.join("");
}

export type MappedHit = {
  start: number;
  end: number;
  search: string;
  alias: string;
  kind: FindingKind;
};

/** Scan global mapping hits (same bounds as apply). Used by apply + verify. */
export function scanMappedHits(
  text: string,
  mappings: MappingEntry[],
  needsSpanOnly: (value: string, kind?: FindingKind) => boolean,
): MappedHit[] {
  const active = mappings.filter((e) => e.decision === "replace");
  if (active.length === 0) return [];

  const root = newNode();
  const add = (search: string, alias: string, kind: FindingKind) => {
    if (isSentinelValue(search) || search.length < MIN_IDENTITY_LENGTH) return;
    if (needsSpanOnly(search, kind)) return;
    // Secrets (when not span-only): folded key + exact case, alphanumeric
    // bounds so `12345678` cannot carve `pid=123456789` / `password` labels.
    const bounded =
      kind === "secret" ||
      kind === "account" ||
      kind === "person_name" ||
      kind === "hostname" ||
      kind === "ipv4" ||
      kind === "ipv6" ||
      kind === "mac";
    const ci =
      kind !== "secret" &&
      (kind === "account" ||
        kind === "person_name" ||
        kind === "hostname" ||
        kind === "email");
    const ipLike = kind === "ipv4" || kind === "ipv6" || kind === "mac";
    const key = foldCase(search);
    let n = root;
    for (let i = 0; i < key.length; i += 1) {
      const ch = key[i]!;
      let nx = n.next.get(ch);
      if (!nx) {
        nx = newNode();
        n.next.set(ch, nx);
      }
      n = nx;
    }
    (n.out ??= []).push({
      len: search.length,
      alias,
      kind,
      bounded,
      ipLike,
      ci,
      search,
    });
  };

  for (const e of active) {
    add(e.original, e.alias, e.kind);
    for (const v of e.variants ?? []) add(v, e.alias, e.kind);
  }

  const lower = foldCase(text);
  const found: MappedHit[] = [];
  for (let i = 0; i < text.length; i += 1) {
    let n = root.next.get(lower[i]!);
    if (!n) continue;
    let best: MappedHit | null = null;
    let j = i;
    while (n) {
      if (n.out) {
        for (const o of n.out) {
          const end = i + o.len;
          if (best && o.len <= best.end - best.start) continue;
          if (!o.ci && text.slice(i, end) !== o.search) continue;
          if (o.bounded) {
            const ok = o.ipLike
              ? ipLikeBoundary(text, i, end, o.kind)
              : o.kind === "secret"
                ? secretBoundary(text, i, end, o.search)
                : boundBefore(text, i, o.kind) && boundAfter(text, end, o.kind);
            if (!ok) continue;
          }
          best = {
            start: i,
            end,
            search: o.search,
            alias: o.alias,
            kind: o.kind,
          };
        }
      }
      j += 1;
      if (j >= text.length) break;
      n = n.next.get(lower[j]!);
    }
    if (best) {
      found.push(best);
      i += best.end - best.start - 1;
    }
  }
  return found;
}

type Out = {
  len: number;
  alias: string;
  kind: FindingKind;
  bounded: boolean;
  ipLike: boolean;
  ci: boolean;
  search: string;
};

type Node = { next: Map<string, Node>; out?: Out[] };

function newNode(): Node {
  return { next: new Map() };
}

type ExactOut = { len: number; search: string };
type ExactNode = { next: Map<string, ExactNode>; out?: ExactOut[] };

function newExactNode(): ExactNode {
  return { next: new Map() };
}

/** Exact-case secret scan for verifyOutput (avoids per-password indexOf). */
export function scanExactSecretHits(
  text: string,
  searches: Iterable<string>,
): MappedHit[] {
  const root = newExactNode();
  let empty = true;
  for (const search of searches) {
    if (!search) continue;
    empty = false;
    let n = root;
    for (let i = 0; i < search.length; i += 1) {
      const ch = search[i]!;
      let nx = n.next.get(ch);
      if (!nx) {
        nx = newExactNode();
        n.next.set(ch, nx);
      }
      n = nx;
    }
    (n.out ??= []).push({ len: search.length, search });
  }
  if (empty) return [];

  const found: MappedHit[] = [];
  for (let i = 0; i < text.length; i += 1) {
    let n = root.next.get(text[i]!);
    if (!n) continue;
    let best: ExactOut | null = null;
    let j = i;
    while (n) {
      if (n.out) {
        for (const o of n.out) {
          if (best && o.len <= best.len) continue;
          const end = i + o.len;
          if (!secretBoundary(text, i, end, o.search)) continue;
          best = o;
        }
      }
      j += 1;
      if (j >= text.length) break;
      n = n.next.get(text[j]!);
    }
    if (best) {
      found.push({
        start: i,
        end: i + best.len,
        search: best.search,
        alias: "",
        kind: "secret",
      });
      i += best.len - 1;
    }
  }
  return found;
}

/** Secret token bounds: no alnum glue; protect syslog timestamps. */
export function secretBoundary(
  s: string,
  start: number,
  end: number,
  search: string,
): boolean {
  const before = start > 0 ? s.charCodeAt(start - 1) : -1;
  const after = end < s.length ? s.charCodeAt(end) : -1;
  const alnum = (c: number) =>
    (c >= 48 && c <= 57) ||
    (c >= 65 && c <= 90) ||
    (c >= 97 && c <= 122);
  if (alnum(before) || alnum(after)) return false;
  if (
    (after === 61 /* = */ || after === 58 /* : */) &&
    /^[A-Za-z]+$/.test(search)
  ) {
    return false;
  }
  if (isBareDateOrTime(search) && isLogTimestampContext(s, start, end)) {
    return false;
  }
  return true;
}

/** IP/MAC/IPv6 token bounds (no partial match inside a longer address). */
function ipLikeBoundary(
  s: string,
  start: number,
  end: number,
  kind: FindingKind,
): boolean {
  const before = start > 0 ? s.charCodeAt(start - 1) : -1;
  const after = end < s.length ? s.charCodeAt(end) : -1;
  const isDigit = (c: number) => c >= 48 && c <= 57;
  const isAlpha = (c: number) =>
    (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
  const isHex = (c: number) =>
    isDigit(c) ||
    (c >= 65 && c <= 70) ||
    (c >= 97 && c <= 102);
  if (kind === "ipv4") {
    if (isDigit(before) || before === 46) return false;
    if (isDigit(after)) return false;
    if (after === 46) {
      const afterDot = end + 1 < s.length ? s.charCodeAt(end + 1) : -1;
      if (isDigit(afterDot) || isAlpha(afterDot)) return false;
    }
    return true;
  }
  return !isHex(before) && !isHex(after);
}

export function isIdent(c: number): boolean {
  return (
    (c >= 65 && c <= 90) ||
    (c >= 97 && c <= 122) ||
    (c >= 48 && c <= 57) ||
    c === 95 ||
    c === 45 ||
    c === 46
  );
}

export function boundBefore(s: string, i: number, kind?: FindingKind): boolean {
  if (i <= 0) return true;
  const b = s.charCodeAt(i - 1);
  if (!isIdent(b)) return true;
  // Filenames: `scan_cni_Haddad.jpg` / `CDI_Marchand.pdf` - underscore
  // separates a person-name token.
  if (kind === "person_name" && b === 95 /* _ */) return true;
  // CLI/PowerShell flag: ` -ComputerName` - leading hyphen is a boundary
  // (unlike an interior hyphen in `srv-web01`).
  if (b === 45 /* - */) {
    const prev = i >= 2 ? s.charCodeAt(i - 2) : -1;
    if (
      prev < 0 ||
      prev === 32 ||
      prev === 9 ||
      prev === 10 ||
      prev === 13 ||
      prev === 34 ||
      prev === 39
    ) {
      return true;
    }
  }
  if (i >= 2 && s.charCodeAt(i - 2) === 92) {
    return [116, 110, 114, 92, 34, 47, 98, 102].includes(b);
  }
  return false;
}

export function boundAfter(s: string, i: number, kind?: FindingKind): boolean {
  if (i >= s.length) return true;
  const c = s.charCodeAt(i);
  if (kind === "person_name" && c === 95 /* _ */) return true;
  if (c === 46) {
    const n = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
    // `Haddad.jpg` - extension after a person name is a boundary.
    if (kind === "person_name") return true;
    return n < 0 || !isIdent(n) || n === 46;
  }
  return !isIdent(c);
}
