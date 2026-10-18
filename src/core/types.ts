/** Detector / finding categories. Keep identifiers brand-agnostic. */
export type FindingKind =
  | "ipv4"
  | "ipv6"
  | "mac"
  | "email"
  | "phone"
  | "hostname"
  | "person_name"
  | "account"
  | "address"
  | "geo"
  | "birth_date"
  | "internal_id"
  | "business_id"
  | "sid"
  | "secret"
  | "custom";

export type Decision = "replace" | "keep";

export type InputFormat = "text" | "jsonl" | "json";

/** IP alias mode. Default preserveClass: private→private, public/doc→RFC 5737. */
export type IpAliasStyle =
  | "preserveClass"
  | "label"
  | "documentation"
  | "structure"
  | "random";

/** Geo coordinates: opaque mask, or round to ~1 km at 2 decimals. */
export type GeoMode = "mask" | "round";

export interface Span {
  start: number;
  end: number;
}

export interface Finding {
  kind: FindingKind;
  /** Exact source text to replace (string content or number token). */
  value: string;
  /** Normalized key used for coherent mapping (e.g. lowercased email). */
  key: string;
  span: Span;
  /** JSON path hint when known (dot-separated key names, no array indices). */
  fieldPath?: string;
  decision: Decision;
}

export interface AliasOptions {
  ipStyle: IpAliasStyle;
  geoMode: GeoMode;
  geoRoundDecimals: number;
}

export interface MappingEntry {
  kind: FindingKind;
  original: string;
  alias: string;
  decision: Decision;
  occurrenceCount: number;
    /** Span-only replace (no global propagate); for short numbers like pid=/size=. */
  spans?: Span[];
    /** Other surface forms of the same value; same alias. */
  variants?: string[];
}

export interface AnalyzeSummary {
  format: InputFormat;
  totalFindings: number;
  uniqueValues: number;
  byKind: Partial<Record<FindingKind, number>>;
}

export interface AnalyzeResult {
  format: InputFormat;
  findings: Finding[];
  mappings: MappingEntry[];
  summary: AnalyzeSummary;
}

export interface ApplyResult {
  output: string;
  mappings: MappingEntry[];
}

export interface LeakHit {
  original: string;
  kind: FindingKind;
  index: number;
}

export interface VerifyResult {
  remaining: LeakHit[];
}

export interface RedactOptions {
  alias: AliasOptions;
    /** When true, internal IDs default to replace (default: keep). */
  redactInternalIds: boolean;
    /** When true, business IDs default to replace (default: keep). */
  redactBusinessIds: boolean;
}

export const DEFAULT_REDACT_OPTIONS: RedactOptions = {
  alias: {
    ipStyle: "preserveClass",
    geoMode: "mask",
    geoRoundDecimals: 2,
  },
  redactInternalIds: false,
  redactBusinessIds: false,
};
