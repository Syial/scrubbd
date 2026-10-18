/** Tokens never learned as account / hostname / person name. */

const ACCOUNT_STOP = new Set(
  [
    "authentication",
    "authorization",
    "authorisation",
    "authenticated",
    "authorized",
    "authorised",
    "unauthorized",
    "unauthorised",
    "accounting",
    "account",
    "login",
    "logon",
    "logout",
    "logoff",
    "signin",
    "signout",
    "unix-session",
    "unix_session",
    "successful",
    "success",
    "failed",
    "failure",
    "denied",
    "allowed",
    "unknown",
    "invalid",
    "expired",
    "locked",
    "disabled",
    "enabled",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "session",
    "connection",
    "request",
    "response",
    "method",
    "protocol",
    "agent",
    "system",
    "service",
    "process",
    "thread",
    "error",
    "warning",
    "info",
    "debug",
    "trace",
    "fatal",
    "critical",
    "notice",
    "identity",
    "started",
    "stopped",
    "opened",
    "closed",
    "cest",
    "cet",
    "utc",
    "gmt",
    "est",
    "edt",
    "pst",
    "pdt",
    "cst",
    "mst",
    "via",
    "mfa",
    "with",
    "from",
    "into",
    "over",
    "under",
    "after",
    "before",
    "about",
    "against",
    "server",
    "attempts",
    "properties",
    "stage",
  ].map((s) => s.toLowerCase()),
);

const HOSTNAME_STOP = new Set(
  [
    ...ACCOUNT_STOP,
    "secrets",
    "secret",
    "nodes",
    "node",
    "pods",
    "pod",
    "services",
    "service",
    "deployments",
    "deployment",
    "replicasets",
    "replicaset",
    "statefulsets",
    "daemonsets",
    "configmaps",
    "configmap",
    "namespaces",
    "namespace",
    "endpoints",
    "endpoint",
    "ingresses",
    "ingress",
    "events",
    "event",
    "jobs",
    "cronjobs",
    "workstation",
    "workstations",
    "interface",
    "interfaces",
    "browsing",
    "web-browsing",
    "ssl",
    "tcp",
    "udp",
    "icmp",
    "http",
    "https",
    "dns",
    "ftp",
    "ssh",
    "rdp",
    "smb",
    "inside",
    "outside",
    "dmz",
    "trust",
    "untrust",
    "any",
    "none",
    "unknown",
  ].map((s) => s.toLowerCase()),
);

const PERSON_STOP_FIRST = new Set(
  [
    "bonjour",
    "bonsoir",
    "salut",
    "hello",
    "hi",
    "dear",
    "cher",
    "chère",
    "chere",
    "madame",
    "monsieur",
    "mme",
    "mlle",
    "merci",
    "thanks",
    "thank",
    "please",
    "computername",
    "scriptblock",
    "filename",
    "displayname",
    "username",
    "hostname",
    "let",
    "lets",
    "let's",
    "new",
    "object",
    "create",
    "update",
    "delete",
    "failed",
    "error",
    "warning",
    "info",
    "from",
    "with",
    "using",
    "via",
    "for",
    "the",
    "and",
    "microsoft",
    "windows",
    "linux",
    "java",
    "python",
    "openssl",
    "encrypt",
    "authority",
    "certificate",
    "common",
    "subject",
    "issuer",
    "mozilla",
    "firefox",
    "chrome",
    "safari",
    "program",
    "programs",
  ].map((s) => s.toLowerCase()),
);

const PERSON_STOP_FULL = new Set(
  [
    "let's encrypt",
    "lets encrypt",
    "new-object",
    "bonjour léa",
    "bonjour lea",
    "common name",
    "distinguished name",
    "r3",
    "r10",
    "r11",
    "r12",
    "r13",
    "isrg root x1",
    "isrg root x2",
    "digicert",
    "globalsign",
    "microsoft",
    "amazon",
    "mozilla firefox",
    "google chrome",
    "program files",
    "internet explorer",
  ].map((s) => s.toLowerCase()),
);

export function isAccountStopword(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (ACCOUNT_STOP.has(v)) return true;
  // Times / durations mistaken for logins: 08:01:12,123
  if (/^\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?$/.test(v)) return true;
  return false;
}

export function isHostnameStopword(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (HOSTNAME_STOP.has(v)) return true;
  if (/^\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?$/.test(v)) return true;
  return false;
}

export function isPersonNameStopword(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/\s+/g, " ");
  if (PERSON_STOP_FULL.has(v)) return true;
  const first = v.split(" ")[0] ?? "";
  if (PERSON_STOP_FIRST.has(first)) return true;
  // CA / product tokens: "Let's Encrypt", "New-Object …"
  if (/^(let'?s|new-object|pscredential)\b/i.test(v)) return true;
  return false;
}

/** True when a multi-word value looks like "Alice Martin", not a sentence. */
export function looksLikePersonNamePhrase(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 80) return false;
  if (isPersonNameStopword(trimmed)) return false;
  if (/[/:=@<>()[\]{}]/.test(trimmed)) return false;
  if (/\bas\b|\bto\b|\bon\b|\bfor\b|\bis\b|\bnot\b|\bthe\b/i.test(trimmed)) {
    return false;
  }
  const parts = trimmed.split(/\s+/);
  if (parts.length < 2 || parts.length > 5) return false;
  // Allow lowercase particles between Proper-Case tokens: El / de / van / von…
  const particle = /^(el|al|de|des|du|da|di|do|dos|van|von|der|den|ten|ter|le|la|af)$/i;
  let proper = 0;
  for (const p of parts) {
    if (particle.test(p)) continue;
    if (!/^[A-ZÀ-ÖØ-Ý][\p{L}'’-]*$/u.test(p)) return false;
    proper += 1;
  }
  return proper >= 2;
}
