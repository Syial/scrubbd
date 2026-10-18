import type { Finding } from "../types";

/** Form-based secret scanners; alias factory emits [SECRET]. */
export function findSecrets(text: string): Finding[] {
  const findings: Finding[] = [];

  findings.push(...findJwt(text));
  findings.push(...findAwsAccessKey(text));
  findings.push(...findGithubToken(text));
  findings.push(...findStripeLikeKey(text));

  return findings;
}

function findJwt(text: string): Finding[] {
  const out: Finding[] = [];
  // eyJ… . eyJ… . signature - three base64url segments
  let i = 0;
  while (i < text.length - 10) {
    if (text.startsWith("eyJ", i)) {
      const end = readJwt(text, i);
      if (end !== null) {
        const value = text.slice(i, end);
        out.push({
          kind: "secret",
          value,
          key: value,
          span: { start: i, end },
          decision: "replace",
        });
        i = end;
        continue;
      }
    }
    i += 1;
  }
  return out;
}

function readJwt(text: string, start: number): number | null {
  let i = start;
  let dots = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (isBase64Url(c)) {
      i += 1;
      continue;
    }
    if (c === 46 /* . */) {
      dots += 1;
      if (dots > 2) return null;
      i += 1;
      continue;
    }
    break;
  }
  if (dots !== 2) return null;
  if (i - start < 20) return null;
  return i;
}

function findAwsAccessKey(text: string): Finding[] {
  const out: Finding[] = [];
  let i = 0;
  while (i < text.length) {
    if (text.startsWith("AKIA", i) || text.startsWith("ASIA", i)) {
      const end = i + 20;
      if (end <= text.length && isAwsKeyBody(text, i, end)) {
        const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
        const next = end < text.length ? text.charCodeAt(end) : -1;
        if (!isAlphaNum(prev) && !isAlphaNum(next)) {
          const value = text.slice(i, end);
          out.push({
            kind: "secret",
            value,
            key: value,
            span: { start: i, end },
            decision: "replace",
          });
          i = end;
          continue;
        }
      }
    }
    i += 1;
  }
  return out;
}

function isAwsKeyBody(text: string, start: number, end: number): boolean {
  for (let i = start + 4; i < end; i += 1) {
    const c = text.charCodeAt(i);
    if (!((c >= 65 && c <= 90) || (c >= 48 && c <= 57))) return false;
  }
  return end - start === 20;
}

function findGithubToken(text: string): Finding[] {
  return findPrefixedToken(text, "ghp_", 36);
}

function findStripeLikeKey(text: string): Finding[] {
  return [
    ...findPrefixedToken(text, "sk_test_", 24),
    ...findPrefixedToken(text, "sk_live_", 24),
    ...findPrefixedToken(text, "rk_test_", 24),
  ];
}

function findPrefixedToken(text: string, prefix: string, minLen: number): Finding[] {
  const out: Finding[] = [];
  let from = 0;
  while (from < text.length) {
    const i = text.indexOf(prefix, from);
    if (i === -1) break;
    let j = i + prefix.length;
    while (j < text.length && isSecretBody(text.charCodeAt(j))) j += 1;
    if (j - i >= minLen) {
      const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
      if (!isAlphaNum(prev)) {
        const value = text.slice(i, j);
        out.push({
          kind: "secret",
          value,
          key: value,
          span: { start: i, end: j },
          decision: "replace",
        });
      }
    }
    from = Math.max(j, i + 1);
  }
  return out;
}

function isBase64Url(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 45 ||
    code === 95
  );
}

function isSecretBody(code: number): boolean {
  return isBase64Url(code) || code === 47 /* / */ || code === 43 /* + */;
}

function isAlphaNum(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57)
  );
}
