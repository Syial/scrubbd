import { shouldRejectSecretValue } from "../secretValueGuards";
import type { Finding } from "../types";

/** Free-text secrets (announced passwords, SNMP, PSK, session ids, …). */
export function findPhraseSecrets(text: string): Finding[] {
  return [
    ...findAnnouncedPasswords(text),
    ...findSnmpCommunity(text),
    ...findCiscoHashes(text),
    ...findPsk(text),
    ...findJsessionId(text),
    ...findPhpSessionId(text),
    ...findOauthCode(text),
    ...findSshKeyBlob(text),
    ...findUrlPasswordParam(text),
    ...findSiblingNameValueSecrets(text),
  ];
}

/** `login?u=x&p=Winter2026!` / `password=` query params. */
function findUrlPasswordParam(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /[?&](?:p|pass|passwd|password|pwd)=([^&\s"'<>]{4,128})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (/^(YES|NO)$/i.test(value)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `urlpwd:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** JSON {"name":"DB_PASSWORD","value":"…"} sibling secrets. */
function findSiblingNameValueSecrets(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /"name"\s*:\s*"(DB_PASSWORD|PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)"\s*,\s*"value"\s*:\s*"([^"]+)"/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[2]!;
    const start = m.index + m[0]!.lastIndexOf(`"${value}"`) + 1;
    out.push({
      kind: "secret",
      value,
      key: `nv:${m[1]}:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  // Reverse order: value before name
  const re2 =
    /"value"\s*:\s*"([^"]+)"\s*,\s*"name"\s*:\s*"(DB_PASSWORD|PASSWORD|SECRET|API_KEY|TOKEN|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)"/gi;
  while ((m = re2.exec(text)) !== null) {
    const value = m[1]!;
    const start = m.index + m[0]!.indexOf(`"${value}"`) + 1;
    out.push({
      kind: "secret",
      value,
      key: `nv:${m[2]}:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findAnnouncedPasswords(text: string): Finding[] {
  const out: Finding[] = [];
  // SQL: PASSWORD '…' / IDENTIFIED BY '…'
  const sql =
    /\b(?:PASSWORD|IDENTIFIED\s+BY)\s+('([^']{4,128})'|"([^"]{4,128})")/gi;
  let m: RegExpExecArray | null;
  while ((m = sql.exec(text)) !== null) {
    const value = m[2] ?? m[3]!;
    const start = m.index + m[0]!.lastIndexOf(value);
    out.push({
      kind: "secret",
      value,
      key: `sqlpwd:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }

  // French: `mot de passe du portail : Summer2026!`
  // Only space/tab around `:`/`=` - never `\s` (would jump a newline onto the
  // next line's timestamp when `password=` is empty).
  const fr =
    /\b(?:le\s+)?(?:mdp|mot\s+de\s+passe)(?:\s+(?:du|de\s+la|de|des)\s+\w+)?[ \t]*[:=][ \t]*([^\s,;<>"'&]{4,64}|['"][^'"]{4,64}['"])/gi;
  while ((m = fr.exec(text)) !== null) {
    pushAnnouncedSecret(out, m);
  }

  // Immediate English `password=…` / `secret: …` - no free words between key and sep
  // (avoids `password cn1Label=attempts` and `password policy updated noso2=reset`).
  const re =
    /\b(?:password|passwd|pwd|passphrase|secret)[ \t]*[:=][ \t]*([^\s,;<>"'&]{4,64}|['"][^'"]{4,64}['"])/gi;
  while ((m = re.exec(text)) !== null) {
    pushAnnouncedSecret(out, m);
  }

  // Announced in prose: `mot de passe du portail : Summer2026!` / `password is X`
  // Only `is/was/est` as the bridge - never bare `=`/`:`, which over-match across
  // neighboring assignments (`password policy updated noso2=reset`).
  const prose =
    /\b(?:(?:le\s+)?(?:mdp|mot\s+de\s+passe)|password|passwd|pwd)(?:\s+\w+){0,3}\s+(?:est|is|was)\s+([^\s,;<>"'&]{4,64})/gi;
  // `Password for user X is Winter2026!`
  const forUser =
    /\bpassword\s+for\s+user\s+\S+\s+is\s+([^\s,;<>"']{4,64})/gi;
  while ((m = prose.exec(text)) !== null) {
    let value = m[1]!;
    let start = m.index + m[0]!.length - value.length;
    while (value.length > 0 && /[):.;,!?]$/.test(value)) value = value.slice(0, -1);
    if (!value || value.length <= 3) continue;
    if (isSecretValueStopword(value)) continue;
    // Prose bridge (`is`/`est`) always has spaces - only reject borrowed fields.
    if (shouldRejectSecretValue(value, true)) continue;
    if (value.startsWith("/") || value.startsWith("~") || /^[A-Za-z]:[\\/]/.test(value)) {
      continue;
    }
    out.push({
      kind: "secret",
      value,
      key: `phrase:${start}:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  while ((m = forUser.exec(text)) !== null) {
    let value = m[1]!;
    let start = m.index + m[0]!.length - value.length;
    while (value.length > 0 && /[):.;,!\r\n]$/.test(value)) value = value.slice(0, -1);
    if (!value || value.length <= 3) continue;
    out.push({
      kind: "secret",
      value,
      key: `phrase:${start}:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** Labels / ordinary words that follow `password :` but are not secrets. */
function isSecretValueStopword(value: string): boolean {
  return /^(server|host|hostname|user|username|login|account|reason|status|code|type|name|label|attempts|policy|link|reset|santa|updated|sent|from|for|with|via|to|of|the|a|an|ok)$/i.test(
    value,
  );
}

function pushAnnouncedSecret(out: Finding[], m: RegExpExecArray): void {
  let value = m[1]!;
  const full = m[0]!;
  let start = m.index + full.length - value.length;
  // Spaces between `=`/`:` and the value → empty-field borrow; glued → real secret.
  const beforeValue = full.slice(0, full.length - m[1]!.length);
  const skippedSpaces = /[:=][ \t]+$/.test(beforeValue);
  if (
    (value.startsWith("'") && value.endsWith("'")) ||
    (value.startsWith('"') && value.endsWith('"'))
  ) {
    value = value.slice(1, -1);
    start += 1;
  }
  // Strip closers / sentence punct - keep `!` (often part of the password).
  while (value.length > 0 && /[):.;,]$/.test(value)) {
    value = value.slice(0, -1);
  }
  if (!value || value.length <= 3) return;
  if (isSecretValueStopword(value)) return;
  if (shouldRejectSecretValue(value, skippedSpaces)) return;
  if (value.startsWith("/") || value.startsWith("~") || /^[A-Za-z]:[\\/]/.test(value)) {
    return;
  }
  out.push({
    kind: "secret",
    value,
    key: `phrase:${start}:${value}`,
    span: { start, end: start + value.length },
    decision: "replace",
  });
}

function findSnmpCommunity(text: string): Finding[] {
  const out: Finding[] = [];
  // `snmp-server community S3cr3tComm RO` / `community=foo`
  const re =
    /\b(?:snmp-server\s+)?community\s+[:=]?\s*([A-Za-z0-9!@#$%^&*._-]{4,64})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (/^(public|private|ro|rw|view)$/i.test(value)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `snmp:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findCiscoHashes(text: string): Finding[] {
  const out: Finding[] = [];
  // Type 5 MD5: $1$salt$hash  / Type 9: $9$salt$hash
  const re = /\$[159]\$[A-Za-z0-9./]{1,64}\$[A-Za-z0-9./]{4,128}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({
      kind: "secret",
      value: m[0]!,
      key: `cisco:${m[0]}`,
      span: { start: m.index, end: m.index + m[0]!.length },
      decision: "replace",
    });
  }
  return out;
}

function findPsk(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\b(?:pre[_-]?shared[_-]?key|psk|shared[_-]?key|ipsec[_-]?key)[ \t]*[:=][ \t]*([A-Za-z0-9!@#$%^&*._=-]{4,128})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `psk:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  // Inline forms: `pre-shared-key MyPre5haredKey` / `crypto isakmp key MyKey address`
  const re2 =
    /\b(?:crypto\s+isakmp\s+key|pre-shared-key|psk)\s+([A-Za-z0-9!@#$%^&*._-]{4,64})\b/gi;
  while ((m = re2.exec(text)) !== null) {
    const value = m[1]!;
    if (/^(address|ipv4|ipv6)$/i.test(value)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `psk:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findJsessionId(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /;jsessionid=([A-Za-z0-9_-]{16,128})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `jsession:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findPhpSessionId(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bPHPSESSID[=:]([A-Fa-f0-9]{26,64})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `phpsess:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  // Bare 32-hex after session-ish labels
  const re2 = /\b(?:session[_-]?id|phpsessid)[ \t]*[:=][ \t]*([A-Fa-f0-9]{32})\b/gi;
  while ((m = re2.exec(text)) !== null) {
    const value = m[1]!;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `phpsess:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findOauthCode(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /[?&]code=([A-Za-z0-9._~%+/-]{12,256})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "secret",
      value,
      key: `oauth:${value}`,
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findSshKeyBlob(text: string): Finding[] {
  const out: Finding[] = [];
  // Base64 openssh key body starting with b3BlbnNzaC1rZXk (openssh-key-v1)
  const re = /\bb3BlbnNzaC1rZXk[A-Za-z0-9+/=]{20,}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({
      kind: "secret",
      value: m[0]!,
      key: `sshkey:${m.index}`,
      span: { start: m.index, end: m.index + m[0]!.length },
      decision: "replace",
    });
  }
  return out;
}
