import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";

/** Quoted secrets / user:pass pairs (PDO, audit -u, …). */
export function findQuotedSecrets(text: string): Finding[] {
  return [
    ...findPdoConstructSecrets(text),
    ...findQuotedUserPass(text),
  ];
}

function findPdoConstructSecrets(text: string): Finding[] {
  const out: Finding[] = [];
  // PDO->__construct('dsn', 'user', 'secret')
  const re =
    /->__construct\(\s*'[^']*'\s*,\s*'([^']*)'\s*,\s*'([^']+)'/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const user = m[1]!;
    const pass = m[2]!;
    if (user && isRedactableAccount(user)) {
      const uStart = m.index + m[0]!.indexOf(`'${user}'`) + 1;
      out.push({
        kind: "account",
        value: user,
        key: user.toLowerCase(),
        span: { start: uStart, end: uStart + user.length },
        decision: "replace",
      });
    }
    if (pass.length >= 4) {
      const pStart = m.index + m[0]!.lastIndexOf(`'${pass}'`) + 1;
      out.push({
        kind: "secret",
        value: pass,
        key: `pdo:${pass}`,
        span: { start: pStart, end: pStart + pass.length },
        decision: "replace",
      });
    }
  }
  return out;
}

/** Audit EXECVE `a2="lea.moreau:Summer2026!"` after a neighbouring `-u`. */
function findQuotedUserPass(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\ba\d+="([A-Za-z0-9._%+-]{1,64}):([^"]{4,128})"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const user = m[1]!;
    const pass = m[2]!;
    if (/^(https?|ftp)$/i.test(user)) continue;
    // Require a nearby `-u` / `--user` in the same audit record.
    const window = text.slice(Math.max(0, m.index - 80), m.index);
    if (!/a\d+="(?:-u|--user)"/.test(window) && !/\s-u\s/.test(window)) {
      continue;
    }
    const full = m[0]!;
    const base = m.index;
    const userRel = full.indexOf(user);
    const passRel = full.lastIndexOf(pass);
    if (isRedactableAccount(user)) {
      out.push({
        kind: "account",
        value: user,
        key: user.toLowerCase(),
        span: { start: base + userRel, end: base + userRel + user.length },
        decision: "replace",
      });
    }
    out.push({
      kind: "secret",
      value: pass,
      key: `upass:${pass}`,
      span: { start: base + passRel, end: base + passRel + pass.length },
      decision: "replace",
    });
  }
  return out;
}
