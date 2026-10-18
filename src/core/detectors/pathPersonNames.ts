import type { Finding } from "../types";
import { normalizePersonNameKey } from "../personName";
import { isPersonNameStopword, looksLikePersonNamePhrase } from "../stopwords";
import { MIN_IDENTITY_LENGTH } from "../sentinels";

/** Person names in paths, filenames, and search queries. */
export function findPathPersonNames(text: string): Finding[] {
  return [
    ...findUnderscoreNames(text),
    ...findQueryPersonNames(text),
    ...findSpacedFolderNames(text),
  ];
}

/** `Candidats/Haddad Yanis` - Proper-Case pair after a path separator (not JSON quotes). */
function findSpacedFolderNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /(?:[/\\])([A-ZÀ-ÖØ-Ý][\p{L}']{1,40})[ \t]+([A-ZÀ-ÖØ-Ý][\p{L}']{1,40})(?=[/\\'"]|$)/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const first = m[1]!;
    const last = m[2]!;
    if (isNamePartStop(first) || isNamePartStop(last)) continue;
    if (!isProperCaseNameToken(first) || !isProperCaseNameToken(last)) continue;
    const value = `${first} ${last}`;
    // Product / OS folders: `Mozilla Firefox`, `Program Files`, not people.
    if (isPersonNameStopword(value) || !looksLikePersonNamePhrase(value)) continue;
    const nameStart = m.index + 1; // after / or \
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start: nameStart, end: nameStart + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** Proper-Case `First_Last` (+ optional `_NN`) in path / filename contexts. */
function findUnderscoreNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /([A-ZÀ-ÖØ-Ý][\p{L}']{1,40})_([A-ZÀ-ÖØ-Ý][\p{L}']{1,40})(?:_\d{1,4})?/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const first = m[1]!;
    const last = m[2]!;
    // File/doc prefixes: CV_Siobhan_OBrien / Contrat_Marchand_Thibault -
    // rewind after the prefix so the real First_Last still matches.
    if (
      /^(CV|RH|ID|DOC|REF|TMP|IMG|PDF|CDI|CDD)$/i.test(first) ||
      isNamePartStop(first)
    ) {
      re.lastIndex = m.index + first.length + 1;
      continue;
    }
    // Reject SCREAMING_SNAKE / ACL labels: STATUS_SUCCESS, GroupPolicy_VPN.
    if (!isProperCaseNameToken(first) || !isProperCaseNameToken(last)) continue;
    if (isNamePartStop(last)) continue;
    const value = m[0]!;
    const phrase = `${first} ${last}`;
    if (isPersonNameStopword(phrase)) continue;
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(phrase),
      span: { start: m.index, end: m.index + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `q=…` search values that look like a person name (plain or URL-encoded). */
function findQueryPersonNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /[?&]q=([^&\s"'<>]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const raw = m[1]!;
    const valueStart = m.index + m[0]!.indexOf(raw);
    const decoded = tryDecode(raw);

    const comma = /^([\p{L}']{2,40})\s*,\s*([\p{L}']{2,40})$/iu.exec(decoded);
    if (comma && !isNamePartStop(comma[1]!) && !isNamePartStop(comma[2]!)) {
      out.push({
        kind: "person_name",
        value: raw,
        key: normalizePersonNameKey(`${comma[1]} ${comma[2]}`),
        span: { start: valueStart, end: valueStart + raw.length },
        decision: "replace",
      });
      continue;
    }

    const tokens = decoded.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;
    const pair = `${tokens[0]} ${tokens[1]}`;
    if (
      !looksLikePersonNamePhrase(pair) &&
      !looksLikeLooseNamePair(tokens[0]!, tokens[1]!)
    ) {
      continue;
    }
    // Replace the whole q= value (name ± trailing city). Substring R checks still pass.
    if (raw.length < MIN_IDENTITY_LENGTH) continue;
    out.push({
      kind: "person_name",
      value: raw,
      key: normalizePersonNameKey(pair),
      span: { start: valueStart, end: valueStart + raw.length },
      decision: "replace",
    });
  }
  return out;
}

/** Proper-Case token: initial capital + at least one lowercase (not VPN, STATUS). */
function isProperCaseNameToken(token: string): boolean {
  if (token.length < 2) return false;
  if (!/^[A-ZÀ-ÖØ-Ý]/.test(token)) return false;
  if (!/[a-zà-ÿ]/.test(token)) return false;
  // Reject mostly-uppercase labels: GroupPolicy is ok; XMLHTTP not a name.
  const lowers = (token.match(/[a-zà-ÿ]/g) ?? []).length;
  return lowers >= Math.min(2, token.length - 1);
}

function looksLikeLooseNamePair(a: string, b: string): boolean {
  if (a.length < 2 || b.length < 2) return false;
  if (isNamePartStop(a) || isNamePartStop(b)) return false;
  return /^[\p{L}']+$/u.test(a) && /^[\p{L}']+$/u.test(b);
}

function tryDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value.replace(/\+/g, " ");
  }
}

function isNamePartStop(part: string): boolean {
  const v = part.toLowerCase();
  return (
    v.length <= 1 ||
    /^(http|https|www|com|org|net|pdf|xlsx|docx|csv|txt|zip|tgz|png|jpg|jpeg|get|post|put|head|options|ssl|tls|tcp|udp|api|v1|v2|files|file|program|programs|mozilla|firefox|chrome|edge|safari|paie|bulletins|bulletin|clients|export|upload|download|search|recherche|status|success|token|expiry|password|secret|policy|group|outside|inside|contrat|facture|candidats|recrutement|scan|cni|cdi|cdd|cv)$/i.test(
      v,
    )
  );
}
