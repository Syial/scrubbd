import { classifyIpv4, type Ipv4Class } from "./detectors/ipv4";
import type { AliasOptions, FindingKind } from "./types";

export interface AliasFactory {
  aliasFor(kind: FindingKind, key: string, original: string): string;
  /** Mark an address as taken so no alias will equal it. */
  reserveIp(address: string): void;
}

function padIndex(index: number): string {
  return String(index).padStart(2, "0");
}

/** Per-session aliases; IP pools use per-class counters. */
export function createAliasFactory(
  options: Pick<AliasOptions, "ipStyle" | "geoMode" | "geoRoundDecimals"> = {
    ipStyle: "preserveClass",
    geoMode: "mask",
    geoRoundDecimals: 2,
  },
): AliasFactory {
  const counters = new Map<FindingKind, number>();
  const ipClassCounters = new Map<string, number>();
  const assigned = new Map<string, string>();
  const usedIpAliases = new Set<string>();

  const next = (kind: FindingKind): number => {
    const current = counters.get(kind) ?? 0;
    const value = current + 1;
    counters.set(kind, value);
    return value;
  };

  const nextIpClass = (cls: string): number => {
    const current = ipClassCounters.get(cls) ?? 0;
    const value = current + 1;
    ipClassCounters.set(cls, value);
    return value;
  };

  return {
    reserveIp(address: string) {
      const trimmed = address.trim();
      if (trimmed) usedIpAliases.add(trimmed);
    },
    aliasFor(kind, key, original) {
      const cacheKey = `${kind}:${key}`;
      const existing = assigned.get(cacheKey);
      if (existing !== undefined) return existing;

      const index = next(kind);
      let alias: string;

      switch (kind) {
        case "ipv4":
        case "ipv6": {
          // Mapped `::ffff:a.b.c.d` findings share the ipv4 key; classify on the v4.
          const forClass =
            kind === "ipv4" && /^::ffff:/i.test(original) ? key : original;
          alias = ipAlias(kind, index, options.ipStyle, forClass, nextIpClass, usedIpAliases);
          break;
        }
        case "mac":
          alias = `[MAC-${padIndex(index)}]`;
          break;
        case "email": {
          // Share identity with login / nginx remote_user: local-part → compte-NN.
          const at = key.indexOf("@");
          const local = (at > 0 ? key.slice(0, at) : key).toLowerCase();
          const accountKey = `account:${local}`;
          let localAlias = assigned.get(accountKey);
          if (localAlias === undefined) {
            const n = next("account");
            localAlias = `compte-${padIndex(n)}`;
            assigned.set(accountKey, localAlias);
          }
          alias = `${localAlias}@domaine-${padIndex(index)}.example`;
          break;
        }
        case "phone":
          alias = `[TEL-${padIndex(index)}]`;
          break;
        case "hostname":
          alias = `hote-${padIndex(index)}`;
          break;
        case "person_name":
          alias = `personne-${padIndex(index)}`;
          break;
        case "account":
          alias = `compte-${padIndex(index)}`;
          break;
        case "address":
          alias = `[ADR-${padIndex(index)}]`;
          break;
        case "geo":
          if (options.geoMode === "round") {
            alias = roundGeoToken(original, options.geoRoundDecimals);
          } else if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(original)) {
            // Keep JSON numbers valid - never inject [GEO-01] into a numeric token.
            alias = "0";
          } else {
            alias = `[GEO-${padIndex(index)}]`;
          }
          break;
        case "birth_date":
          alias = `[BIRTH-${padIndex(index)}]`;
          break;
        case "internal_id":
          alias = `[ID-${padIndex(index)}]`;
          break;
        case "business_id":
          alias = `[BIZ-${padIndex(index)}]`;
          break;
        case "sid":
          alias = `S-1-5-21-0-0-0-${1000 + index}`;
          break;
        case "secret":
          alias = "[SECRET]";
          break;
        case "custom":
          alias = `[CUSTOM-${padIndex(index)}]`;
          break;
        default: {
          const _exhaustive: never = kind;
          alias = `[VALUE-${padIndex(index)}]`;
          void _exhaustive;
        }
      }

      assigned.set(cacheKey, alias);
      return alias;
    },
  };
}

function roundGeoToken(original: string, decimals: number): string {
  const value = Number(original);
  if (!Number.isFinite(value)) return "[GEO]";
  return value.toFixed(Math.max(0, Math.min(8, decimals)));
}

function ipAlias(
  kind: "ipv4" | "ipv6",
  _globalIndex: number,
  style: AliasOptions["ipStyle"],
  original: string,
  nextIpClass: (cls: string) => number,
  used: Set<string>,
): string {
  if (kind === "ipv6") {
    if (style === "label") return claimIp(`[IP-${padIndex(nextIpClass("label"))}]`, used);
    const n = nextIpClass("ipv6");
    return claimIp(`2001:db8::${n.toString(16)}`, used);
  }

  switch (style) {
    case "label":
      return claimIp(`[IP-${padIndex(nextIpClass("label"))}]`, used);
    case "preserveClass":
      return ipv4PreserveClass(original, nextIpClass, used);
    case "documentation":
      return claimDocOrLabel(nextIpClass("documentation"), used);
    case "structure":
    case "random":
      return ipv4PreserveClass(original, nextIpClass, used);
    default: {
      const _exhaustive: never = style;
      void _exhaustive;
      return ipv4PreserveClass(original, nextIpClass, used);
    }
  }
}

function ipv4PreserveClass(
  original: string,
  nextIpClass: (cls: string) => number,
  used: Set<string>,
): string {
  const cls = classifyIpv4(original);
  const index = nextIpClass(cls);
  const [hi, mid, lo] = hostFromIndex(index);

  let candidate: string;
  switch (cls) {
    case "private_10":
      candidate = `10.${hi}.${mid}.${lo}`;
      break;
    case "private_172":
      candidate = `172.${16 + (hi % 16)}.${mid}.${lo}`;
      break;
    case "private_192":
      candidate = `192.168.${mid}.${lo}`;
      break;
    case "documentation":
    case "public":
      return claimDocOrLabel(index, used);
    case "loopback":
    case "link_local":
    case "multicast":
    case "other":
      return claimIp(`[IP-${padIndex(index)}]`, used);
    default: {
      const _exhaustive: never = cls;
      void _exhaustive;
      return claimDocOrLabel(index, used);
    }
  }

  // Never alias an address to itself; never reuse an alias.
  if (candidate === original || used.has(candidate)) {
    return claimDocOrLabel(index + 1000, used);
  }
  used.add(candidate);
  return candidate;
}

/** Map into RFC 5737 /24s (per-class), then opaque labels. */
function claimDocOrLabel(index: number, used: Set<string>): string {
  const ranges = [
    [192, 0, 2],
    [198, 51, 100],
    [203, 0, 113],
  ] as const;

  // Try index and a few bumps to avoid collisions / identity.
  for (let bump = 0; bump < 800; bump += 1) {
    const n = index + bump;
    if (n <= 762) {
      const range = ranges[(n - 1) % 3]!;
      const host = (Math.floor((n - 1) / 3) % 254) + 1;
      const candidate = `${range[0]}.${range[1]}.${range[2]}.${host}`;
      if (!used.has(candidate)) {
        used.add(candidate);
        return candidate;
      }
    } else {
      const candidate = `[IP-${padIndex(n)}]`;
      if (!used.has(candidate)) {
        used.add(candidate);
        return candidate;
      }
    }
  }
  const fallback = `[IP-${padIndex(index)}-${used.size}]`;
  used.add(fallback);
  return fallback;
}

function claimIp(alias: string, used: Set<string>): string {
  if (!used.has(alias)) {
    used.add(alias);
    return alias;
  }
  let n = 2;
  while (used.has(`${alias}~${n}`)) n += 1;
  const next = `${alias}~${n}`;
  used.add(next);
  return next;
}

function hostFromIndex(index: number): [number, number, number] {
  const n = Math.max(1, index);
  const low = ((n * 37) % 254) + 1;
  const mid = (n * 13) % 256;
  const high = (n * 7) % 256;
  return [high, mid, low];
}

export type { Ipv4Class };
