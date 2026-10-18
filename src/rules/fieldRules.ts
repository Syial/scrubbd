/** Field classification from field NAME and PATH. First matching rule wins. */

/** Matches FindingKind in core/types. */
export type FieldKind =
  | "email"
  | "phone"
  | "ip"
  | "mac"
  | "hostname"
  | "address"
  | "geo"
  | "birth_date"
  | "person_name"
  | "account"
  | "internal_id"
  | "business_id"
  | "secret";

export type FieldVerdict =
  /** Run this detector on the field value. */
  | { readonly type: "detect"; readonly kind: FieldKind; readonly rule: string }
  /** Name is ambiguous; value shape picks among candidates, else fallback. */
  | {
      readonly type: "ambiguous";
      readonly candidates: readonly FieldKind[];
      readonly fallback: FieldKind;
      readonly rule: string;
    }
  /** Leave field untouched; skip free-text detectors too. */
  | { readonly type: "protected"; readonly rule: string };

export interface Names {
  /** Normalized names equal to the field name. */
  readonly exact?: readonly string[];
  /** Name equals token or starts with `token_`. */
  readonly prefix?: readonly string[];
  /** Name equals token or ends with `_token`. */
  readonly suffix?: readonly string[];
}

export interface LeafRule {
  readonly id: string;
  readonly names: Names;
  readonly verdict: FieldVerdict;
}

export interface PathRule {
  readonly id: string;
  /** Normalized path segments. */
  readonly path: readonly string[];
  /** `start` = path prefix; `end` = path suffix. */
  readonly anchor: "start" | "end";
  readonly verdict: FieldVerdict;
}

/** Ignore keys longer than this (not real field names). */
const MAX_FIELD_NAME_LENGTH = 128;
/** Cap caches when logs use dynamic id-as-key fields. */
const MAX_CACHE_ENTRIES = 4096;

const normalizedCache = new Map<string, string>();

function remember<K, V>(cache: Map<K, V>, key: K, value: V): void {
  if (cache.size >= MAX_CACHE_ENTRIES) cache.clear();
  cache.set(key, value);
}

function computeNormalized(raw: string): string {
  return raw
    .normalize("NFD")
    .replace(/\p{M}+/gu, "") // strip accents
    .replace(/IPv([46])/g, "_ipv$1_") // keep ipv4 / ipv6 as one token
    .replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, "$1_$2") // userId → user_Id
    .replace(/(\p{Lu}+)(\p{Lu}\p{Ll})/gu, "$1_$2") // IPAddress → IP_Address
    .replace(/[^\p{L}\p{N}]+/gu, "_") // punctuation → `_`
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
}

/** `targetUserName`, `target-user-name`, `Target.User.Name` → `target_user_name`. */
export function normalizeFieldName(raw: string): string {
  if (raw.length > MAX_FIELD_NAME_LENGTH) return "";
  const cached = normalizedCache.get(raw);
  if (cached !== undefined) return cached;
  const result = computeNormalized(raw);
  remember(normalizedCache, raw, result);
  return result;
}

const detect = (id: string, kind: FieldKind, names: Names): LeafRule => ({
  id,
  names,
  verdict: { type: "detect", kind, rule: id },
});

const ambiguous = (
  id: string,
  candidates: readonly FieldKind[],
  fallback: FieldKind,
  names: Names,
): LeafRule => ({
  id,
  names,
  verdict: { type: "ambiguous", candidates, fallback, rule: id },
});

const protect = (id: string, names: Names): LeafRule => ({
  id,
  names,
  verdict: { type: "protected", rule: id },
});

const pathProtect = (id: string, path: readonly string[], anchor: "start" | "end"): PathRule => ({
  id,
  path,
  anchor,
  verdict: { type: "protected", rule: id },
});

const pathDetect = (
  id: string,
  kind: FieldKind,
  path: readonly string[],
  anchor: "start" | "end",
): PathRule => ({
  id,
  path,
  anchor,
  verdict: { type: "detect", kind, rule: id },
});

export const PATH_RULES: readonly PathRule[] = [
  // Wazuh rule.* / decoder.* are analysis metadata, not PII.
  pathProtect("wazuh-rule-subtree", ["rule"], "start"),
  pathProtect("wazuh-decoder-subtree", ["decoder"], "start"),
  // Bare `name` is vague; path parent makes it specific.
  // Skip agent.id (technical id, not sensitive).
  pathDetect("wazuh-agent-name", "hostname", ["agent", "name"], "end"),
  pathDetect("wazuh-manager-name", "hostname", ["manager", "name"], "end"),
  pathDetect("ecs-user-name", "account", ["user", "name"], "end"),
  pathDetect("ecs-host-name", "hostname", ["host", "name"], "end"),
  pathDetect("slack-profile-name", "account", ["user_profile", "name"], "end"),
  // Under a person-like parent, `name` is a person name.
  ...["contact", "contacts", "customer", "customers", "person", "employee", "patient", "recipient", "recipients", "applicant"].map(
    (parent) => pathDetect(`person-parent-${parent}`, "person_name", [parent, "name"], "end"),
  ),
];

export const LEAF_RULES: readonly LeafRule[] = [
  // Token-like names that are flags, not secrets (before secret rules).
  // Windows 4624 elevatedToken is %%1842 / %%1843 (yes/no).
  protect("windows-token-flags", {
    exact: ["elevated_token"],
    prefix: ["token_elevation"],
  }),
  // Application names must not fall through to `*_display_name` → person_name.
  protect("app-display-early", {
    exact: [
      "app_display_name",
      "application_name",
      "app_name",
      "product_name",
      "application_display_name",
    ],
  }),
  // Secrets first (beats hash/tech rules). Replace, do not alias.
  detect("secret-names", "secret", {
    exact: [
      "password",
      "passwd",
      "pwd",
      "passphrase",
      "secret",
      "token",
      "access_token",
      "refresh_token",
      "id_token",
      "auth_token",
      "bearer",
      "authorization",
      "cookie",
      "set_cookie",
      "session_id",
      "session_token",
      "sessionid",
      "api_key",
      "apikey",
      "private_key",
      "privatekey",
      "client_secret",
      "secret_key",
      "secret_access_key",
      "secretkey",
      "password_hash",
      "password_hint",
      "credential",
      "credentials",
      "iban",
      "pre_shared_key",
      "psk",
      "community",
      "snmp_community",
    ],
    suffix: [
      "password",
      "passwd",
      "secret",
      "token",
      "api_key",
      "apikey",
      "private_key",
      "secret_key",
      "secret_access_key",
      "iban",
    ],
  }),

  // Boolean / status flags.
  protect("flag-like", {
    prefix: ["is", "has", "can", "should"],
    suffix: ["verified", "confirmed", "enabled", "disabled", "valid", "sent", "required", "optional"],
  }),

  // Postal addresses (before numeric-measure rules catch zip_code).
  detect("postal-address", "address", {
    exact: [
      "billing_address",
      "shipping_address",
      "delivery_address",
      "home_address",
      "work_address",
      "postal_address",
      "mailing_address",
      "street_address",
      "address_line_1",
      "address_line_2",
      "address_line1",
      "address_line2",
      "address1",
      "address2",
      "adresse",
      "adresse_postale",
      "adresse_facturation",
      "adresse_livraison",
      "street",
      "rue",
      "postal_code",
      "zip",
      "zipcode",
      "zip_code",
      "code_postal",
    ],
    suffix: ["adresse", "street", "rue", "postal_code", "zip_code"],
  }),

  // Birth dates (before generic *_date timestamps).
  detect("birth-date", "birth_date", {
    exact: [
      "birth_date",
      "birthdate",
      "date_of_birth",
      "dob",
      "birthday",
      "date_naissance",
      "naissance",
    ],
    suffix: ["birthdate", "birth_date", "date_of_birth", "birthday"],
  }),

  // Protect timestamps / versions / hashes (phone, card, IP false positives).
  protect("timestamp-like", {
    exact: ["timestamp", "time", "datetime", "date", "epoch"],
    suffix: ["time", "at", "timestamp", "datetime", "date", "epoch"],
  }),
  protect("version-like", {
    exact: ["version", "fileversion", "appversion", "osversion", "agentversion", "productversion"],
    suffix: ["version"],
  }),
  protect("hash-like", {
    exact: ["hash", "hashes", "md5", "sha1", "sha256", "sha512", "imphash", "checksum", "digest"],
    suffix: ["hash", "md5", "sha1", "sha256", "sha512", "checksum", "digest"],
  }),
  // Correlation ids analysts need to join events.
  protect("correlation-id", {
    exact: [
      "request_id",
      "trace_id",
      "span_id",
      "correlation_id",
      "event_id",
      // Fortinet logid looks like a phone if not protected
      "logid",
      "log_id",
      "rule_id",
      "process_id",
      "parent_process_id",
      "pid",
      "ppid",
      "thread_id",
    ],
    suffix: [
      "request_id",
      "trace_id",
      "span_id",
      "correlation_id",
      "event_id",
      "rule_id",
      "process_id",
      "pid",
      "thread_id",
    ],
  }),
  // Numeric measures (long digit runs look like phones/cards).
  protect("numeric-measure", {
    exact: [
      "amount",
      "price",
      "total",
      "count",
      "size",
      "bytes",
      "duration",
      "latency",
      "port",
      "status",
      "status_code",
      "http_status",
    ],
    suffix: [
      "amount",
      "usd",
      "eur",
      "count",
      "size",
      "bytes",
      "ms",
      "seconds",
      "port",
      "status",
      "duration",
      "latency",
      "total",
    ],
  }),

  // Identity / network. Specific mac_address / ip_address before generic *_address.
  detect("email", "email", {
    exact: ["email", "e_mail", "mail", "courriel", "email_address", "mail_address"],
    prefix: ["email"],
    suffix: ["email", "mail", "courriel"],
  }),
  detect("phone", "phone", {
    exact: [
      "phone",
      "mobile",
      "telephone",
      "telephones",
      "tel",
      "fixe",
      "msisdn",
      "cell",
      "cellphone",
      "gsm",
      "fax",
      "phone_number",
      "mobile_number",
      "numero_telephone",
    ],
    suffix: [
      "phone",
      "mobile",
      "tel",
      "telephone",
      "telephones",
      "fixe",
      "msisdn",
      "phone_number",
      "mobile_number",
      "fax",
    ],
  }),
  detect("mac", "mac", {
    exact: [
      "mac",
      "mac_address",
      "mac_addr",
      "macaddr",
      "hwaddr",
      "hw_addr",
      "hardware_address",
      "smac",
      "dmac",
    ],
    suffix: ["mac", "mac_address", "mac_addr", "smac", "dmac"],
  }),

  detect("ip", "ip", {
    exact: [
      "ip",
      "ips",
      "ipv4",
      "ipv6",
      "ip_address",
      "ip_addresses",
      "ip_addr",
      "ipaddr",
      "ipaddress",
      "srcip",
      "dstip",
      "clientip",
      "remoteip",
      "serverip",
      "sourceip",
      "destinationip",
      "x_forwarded_for",
      "forwarded_for",
      "remote_addr",
      "client_addr",
      "peer_ip",
      "real_ip",
      "x_real_ip",
      "ip_publique",
      "ip_attribuee",
      "ip_inscription",
    ],
    suffix: [
      "ip",
      "ipv4",
      "ipv6",
      "ip_address",
      "ip_addr",
      "ip_addresses",
      "ip_publique",
      "ip_attribuee",
    ],
  }),
  // Bare `address`: IP, MAC, or postal; value decides.
  ambiguous("address-like", ["ip", "mac", "address"], "address", {
    suffix: ["address", "addr"],
  }),
  // Bare `host`: IP or hostname.
  ambiguous("host-like", ["ip", "hostname"], "hostname", {
    suffix: ["host"],
  }),
  detect("hostname", "hostname", {
    exact: [
      "hostname",
      "host_name",
      "computer",
      "computer_name",
      "workstation",
      "workstation_name",
      "machine",
      "machine_name",
      "node_name",
      "nodename",
      "device_name",
      "device",
      "appareil",
      "fqdn",
      "netbios_name",
      // Fortinet / firewall device and src/dst host names
      "devname",
      "dev_name",
      "srcname",
      "src_name",
      "dstname",
      "dst_name",
      // Glue forms common in Windows / Wazuh logs
      "computername",
      "machinename",
      "workstationname",
      "systemname",
      "system_name",
      "servername",
      "server_name",
      // CEF
      "shost",
      "dhost",
      // Windows lockout / logon source machine (sometimes stuffed in DomainName)
      "target_domain_name",
      "subject_domain_name",
      // NOTE: bare `resource` is NOT a hostname - K8s objectRef.resource is
      // "secrets"/"nodes". LEEF `resource=srv-…` is handled in cefFields.
    ],
    suffix: [
      "hostname",
      "system_name",
      "server_name",
      "host_name",
      "computer_name",
      "workstation_name",
      "machine_name",
      "device_name",
      "fqdn",
      "appareil",
      "shost",
      "dhost",
    ],
  }),
  detect("geo", "geo", {
    exact: [
      "lat",
      "lon",
      "lng",
      "latitude",
      "longitude",
      "geo",
      "geolocation",
      "gps",
      "coordinates",
      "coords",
      "cs5", // often paired with cs5Label=geo
    ],
    suffix: ["lat", "lon", "lng", "latitude", "longitude", "coordinates"],
  }),
  // Person names (aliasing differs from accounts).
  detect("person-name", "person_name", {
    exact: [
      "full_name",
      "fullname",
      "display_name",
      "displayname",
      "customer_name",
      "contact_name",
      "first_name",
      "firstname",
      "last_name",
      "lastname",
      "given_name",
      "family_name",
      "middle_name",
      "maiden_name",
      "surname",
      "prenom",
      // FR `nom` is usually a person; drop if your logs reuse it.
      "nom",
      "nom_prenom",
      "prenom_nom",
      "nom_complet",
      "nom_famille",
      "nom_de_famille",
      "cn",
      "sn",
      "givenname",
      "real_name",
    ],
    suffix: [
      "full_name",
      "first_name",
      "last_name",
      "display_name",
      "surname",
      "given_name",
      "family_name",
      "real_name",
    ],
  }),
  // Accounts (DOMAIN\\user, user@domain).
  detect("account", "account", {
    exact: [
      "username",
      "user_name",
      "user",
      "utilisateur",
      "login",
      "account",
      "account_name",
      "acct",
      "srcuser",
      "dstuser",
      "src_user",
      "dst_user",
      "user_principal_name",
      "upn",
      "sam_account_name",
      "samaccountname",
      "logon_user",
      "target_user",
      "subject_user",
      "target_user_name",
      "subject_user_name",
      // CEF / LEEF
      "suser",
      "duser",
      "usrname",
      "srcuser",
      "dstuser",
      "actor",
    ],
    suffix: [
      "username",
      "user_name",
      "user",
      "utilisateur",
      "login_name",
      "account_name",
      "principal_name",
      "suser",
      "duser",
      "usrname",
      "actor",
    ],
  }),
  // Internal identity ids (user/device in source system).
  detect("internal-id", "internal_id", {
    exact: [
      "user_id",
      "userid",
      "customer_id",
      "customerid",
      "account_id",
      "accountid",
      "device_id",
      "deviceid",
      "member_id",
      "person_id",
      "employee_id",
      "patient_id",
    ],
    suffix: [
      "user_id",
      "customer_id",
      "account_id",
      "device_id",
      "member_id",
      "person_id",
      "employee_id",
      "patient_id",
    ],
  }),
  // Business ids (kept by default; UI option later).
  detect("business-id", "business_id", {
    exact: ["invoice_id", "order_id", "ticket_id", "invoice_number", "order_number"],
    suffix: ["invoice_id", "order_id", "ticket_id", "invoice_number", "order_number"],
  }),
];

interface CompiledLeafRule {
  readonly exact: ReadonlySet<string>;
  readonly prefixes: readonly string[];
  readonly suffixes: readonly string[];
  readonly verdict: FieldVerdict;
}

function compileLeafRule(rule: LeafRule): CompiledLeafRule {
  const { exact = [], prefix = [], suffix = [] } = rule.names;
  return {
    // Bare tokens also match when they are the whole field name.
    exact: new Set([...exact, ...prefix, ...suffix]),
    prefixes: prefix.map((token) => `${token}_`),
    suffixes: suffix.map((token) => `_${token}`),
    verdict: rule.verdict,
  };
}

const COMPILED_LEAF_RULES: readonly CompiledLeafRule[] = LEAF_RULES.map(compileLeafRule);

function indexPathRules(
  rules: readonly PathRule[],
  anchor: "start" | "end",
): ReadonlyMap<string, readonly PathRule[]> {
  const index = new Map<string, PathRule[]>();
  for (const rule of rules) {
    if (rule.anchor !== anchor) continue;
    const key = anchor === "start" ? rule.path[0] : rule.path[rule.path.length - 1];
    if (key === undefined) continue;
    const bucket = index.get(key);
    if (bucket) bucket.push(rule);
    else index.set(key, [rule]);
  }
  return index;
}

const PATH_RULES_BY_START = indexPathRules(PATH_RULES, "start");
const PATH_RULES_BY_END = indexPathRules(PATH_RULES, "end");

function matchesLeafRule(name: string, rule: CompiledLeafRule): boolean {
  if (rule.exact.has(name)) return true;
  for (const prefix of rule.prefixes) if (name.startsWith(prefix)) return true;
  for (const suffix of rule.suffixes) if (name.endsWith(suffix)) return true;
  return false;
}

const leafCache = new Map<string, FieldVerdict | null>();

function classifyLeaf(name: string): FieldVerdict | null {
  if (name === "") return null;
  const cached = leafCache.get(name);
  if (cached !== undefined) return cached;
  let result: FieldVerdict | null = null;
  for (const rule of COMPILED_LEAF_RULES) {
    if (matchesLeafRule(name, rule)) {
      result = rule.verdict;
      break;
    }
  }
  remember(leafCache, name, result);
  return result;
}

function segmentsStartWith(segments: readonly string[], wanted: readonly string[]): boolean {
  if (segments.length < wanted.length) return false;
  for (let i = 0; i < wanted.length; i++) {
    const segment = segments[i];
    if (segment === undefined || normalizeFieldName(segment) !== wanted[i]) return false;
  }
  return true;
}

function segmentsEndWith(segments: readonly string[], wanted: readonly string[]): boolean {
  const offset = segments.length - wanted.length;
  if (offset < 0) return false;
  for (let i = 0; i < wanted.length; i++) {
    const segment = segments[offset + i];
    if (segment === undefined || normalizeFieldName(segment) !== wanted[i]) return false;
  }
  return true;
}

/** Flattened exports (Elastic/Wazuh) use one dotted key. */
function expandFlattenedKey(path: readonly string[]): readonly string[] {
  const only = path[0];
  if (path.length === 1 && only !== undefined && only.length <= 512 && only.includes(".")) {
    return only.split(".");
  }
  return path;
}

/** Classify by key path (array indexes omitted). Null if no rule matches. */
export function classifyField(path: readonly string[]): FieldVerdict | null {
  const segments = expandFlattenedKey(path);
  const firstRaw = segments[0];
  const lastRaw = segments[segments.length - 1];
  if (firstRaw === undefined || lastRaw === undefined) return null;

  const startRules = PATH_RULES_BY_START.get(normalizeFieldName(firstRaw));
  if (startRules) {
    for (const rule of startRules) {
      if (segmentsStartWith(segments, rule.path)) return rule.verdict;
    }
  }

  const last = normalizeFieldName(lastRaw);
  const endRules = PATH_RULES_BY_END.get(last);
  if (endRules) {
    for (const rule of endRules) {
      if (segmentsEndWith(segments, rule.path)) return rule.verdict;
    }
  }

  const leaf = classifyLeaf(last);
  if (leaf?.type === "ambiguous" && segments.length >= 2) {
    // Ambiguous leaf: retry as parent_leaf (IP.Address, billing.address).
    const parentRaw = segments[segments.length - 2];
    if (parentRaw !== undefined) {
      const refined = classifyLeaf(`${normalizeFieldName(parentRaw)}_${last}`);
      if (refined !== null && refined.type !== "ambiguous") return refined;
    }
  }
  return leaf;
}

/** True when no detector should touch this field. */
export function isProtectedField(path: readonly string[]): boolean {
  return classifyField(path)?.type === "protected";
}

/** @deprecated Prefer classifyField (path, protected, ambiguous). */
export function classifyFieldName(fieldName: string): FieldKind | null {
  const verdict = classifyField([fieldName]);
  if (verdict === null || verdict.type === "protected") return null;
  return verdict.type === "detect" ? verdict.kind : verdict.fallback;
}

/** @deprecated Prefer isProtectedField. */
export function isIpv4ExcludedField(fieldName: string): boolean {
  return isProtectedField([fieldName]);
}
