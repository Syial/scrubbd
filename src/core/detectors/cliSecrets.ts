import { foldCase } from "../fold";
import { isBareDateOrTime } from "../secretValueGuards";
import type { Finding } from "../types";

/** CLI password flags (-p, --password=, sshpass, net user, …). */
export function findCliSecrets(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);

  // Sticky -p / -P without space: mysql -pS3cr3tRoot, -uroot
  for (const flag of ["-p", "-P", "-w"]) {
    let from = 0;
    while (from < text.length) {
      const idx = text.indexOf(flag, from);
      if (idx === -1) break;
      if (idx > 0 && isIdent(text.charCodeAt(idx - 1))) {
        from = idx + 1;
        continue;
      }
      const after = idx + flag.length;
      if (after >= text.length) break;
      const next = text.charCodeAt(after);
      // `-p ` or `-p'` → value in next token / quotes
      if (next === 32 || next === 9 || next === 61 /* = */) {
        const parsed = readQuotedOrToken(text, next === 61 ? after + 1 : after);
        if (parsed && looksSecret(parsed.value)) {
          out.push(secret(parsed.value, parsed.start, parsed.end));
        }
        from = parsed?.end ?? after + 1;
        continue;
      }
      // Sticky `-pS3cr3tRoot` (not `-password` / `-passwd` / PowerShell `-Properties`)
      if (
        flag.length === 2 &&
        isSecretStart(next) &&
        !lower.startsWith("password", after) &&
        !lower.startsWith("asswd", after) &&
        !lower.startsWith("assword", after) &&
        !lower.startsWith("roperties", after)
      ) {
        let j = after;
        while (j < text.length && !isCliEnd(text.charCodeAt(j))) j += 1;
        const value = text.slice(after, j);
        // Pure letters = CLI switch name (`-Properties`), not a sticky password.
        if (/^[A-Za-z]+$/.test(value)) {
          from = j;
          continue;
        }
        if (looksSecret(value)) out.push(secret(value, after, j));
        from = j;
        continue;
      }
      from = after;
    }
  }

  // --password= / --password /
  for (const key of ["--password", "--passwd", "--pwd"]) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(key, from);
      if (idx === -1) break;
      let i = idx + key.length;
      if (text.charCodeAt(i) === 61) i += 1;
      else if (text.charCodeAt(i) === 32) {
        while (text.charCodeAt(i) === 32) i += 1;
      } else {
        from = idx + key.length;
        continue;
      }
      const parsed = readQuotedOrToken(text, i);
      if (parsed && looksSecret(parsed.value)) {
        out.push(secret(parsed.value, parsed.start, parsed.end));
      }
      from = parsed?.end ?? i + 1;
    }
  }

  // sshpass -p '…'
  let sp = 0;
  while (sp < text.length) {
    const idx = lower.indexOf("sshpass", sp);
    if (idx === -1) break;
    const p = text.indexOf("-p", idx);
    if (p !== -1 && p < idx + 20) {
      const parsed = readQuotedOrToken(text, p + 2);
      if (parsed && looksSecret(parsed.value)) {
        out.push(secret(parsed.value, parsed.start, parsed.end));
      }
    }
    sp = idx + 7;
  }

  // openssl … -k "MyKey"
  let ok = 0;
  while (ok < text.length) {
    const idx = text.indexOf(" -k ", ok);
    if (idx === -1) break;
    const parsed = readQuotedOrToken(text, idx + 4);
    if (parsed && looksSecret(parsed.value)) {
      out.push(secret(parsed.value, parsed.start, parsed.end));
    }
    ok = idx + 4;
  }

  // net user NAME [PASSWORD|/add]
  const netUser = /\bnet\s+user\s+(\S+)(?:\s+(\S+))?/gi;
  let m: RegExpExecArray | null;
  while ((m = netUser.exec(text)) !== null) {
    const name = m[1]!;
    if (!name.startsWith("/") && !name.startsWith("-") && /[A-Za-z]/.test(name)) {
      const nStart = m.index + m[0]!.indexOf(name);
      out.push({
        kind: "account",
        value: name,
        key: name.toLowerCase(),
        span: { start: nStart, end: nStart + name.length },
        decision: "replace",
      });
    }
    const value = m[2];
    if (value && !value.startsWith("/") && !value.startsWith("-") && looksSecret(value)) {
      const start = m.index + m[0]!.length - value.length;
      out.push(secret(value, start, start + value.length));
    }
  }

  // htpasswd -b … user PASS
  const ht = /\bhtpasswd\b[^\\n]*\s(\S+)$/gim;
  while ((m = ht.exec(text)) !== null) {
    const value = m[1]!;
    if (looksSecret(value)) {
      const start = m.index + m[0]!.length - value.length;
      out.push(secret(value, start, start + value.length));
    }
  }

  // echo "pass" | sudo -S
  const echoPipe = /\becho\s+(['"])([^'"]+)\1\s*\|\s*sudo\s+-S/gi;
  while ((m = echoPipe.exec(text)) !== null) {
    const value = m[2]!;
    if (looksSecret(value)) {
      const start = m.index + m[0]!.indexOf(value);
      out.push(secret(value, start, start + value.length));
    }
  }

  // ConvertTo-SecureString 'pass'
  const cts = /ConvertTo-SecureString\s+(['"])([^'"]+)\1/gi;
  while ((m = cts.exec(text)) !== null) {
    const value = m[2]!;
    const start = m.index + m[0]!.indexOf(value);
    out.push(secret(value, start, start + value.length));
  }

  // NetworkCredential('user','pass','domain') - 2nd quoted arg is the password
  const nc =
    /NetworkCredential\s*\(\s*'([^']*)'\s*,\s*'([^']+)'/gi;
  while ((m = nc.exec(text)) !== null) {
    const user = m[1]!;
    const pass = m[2]!;
    if (user.length >= 2) {
      const uStart = m.index + m[0]!.indexOf(`'${user}'`) + 1;
      out.push({
        kind: "account",
        value: user,
        key: user.toLowerCase(),
        span: { start: uStart, end: uStart + user.length },
        decision: "replace",
      });
    }
    if (looksSecret(pass)) {
      const pStart = m.index + m[0]!.lastIndexOf(`'${pass}'`) + 1;
      out.push(secret(pass, pStart, pStart + pass.length));
    }
  }

  // schtasks … /rp PASSWORD  /  wmic … /password:"…"
  for (const flag of ["/rp", "/password:"]) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(flag, from);
      if (idx === -1) break;
      let i = idx + flag.length;
      if (flag === "/rp") {
        while (i < text.length && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) {
          i += 1;
        }
      }
      const parsed = readQuotedOrToken(text, i);
      if (parsed && looksSecret(parsed.value)) {
        out.push(secret(parsed.value, parsed.start, parsed.end));
      }
      from = parsed?.end ?? i + 1;
    }
  }

  // HTTP Basic auth: `Basic base64…`
  const basic = /\bBasic\s+([A-Za-z0-9+/=]{12,})/g;
  while ((m = basic.exec(text)) !== null) {
    const full = m[0]!;
    out.push(secret(full, m.index, m.index + full.length));
  }

  return out;
}

function secret(value: string, start: number, end: number): Finding {
  return {
    kind: "secret",
    value,
    key: `cli:${start}:${value}`,
    span: { start, end },
    decision: "replace",
  };
}

function readQuotedOrToken(
  text: string,
  start: number,
): { start: number; end: number; value: string } | null {
  let i = start;
  while (i < text.length && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) {
    i += 1;
  }
  if (i >= text.length) return null;
  const q = text.charCodeAt(i);
  if (q === 34 || q === 39) {
    let j = i + 1;
    while (j < text.length && text.charCodeAt(j) !== q) j += 1;
    if (j >= text.length) return null;
    return { start: i + 1, end: j, value: text.slice(i + 1, j) };
  }
  let j = i;
  while (j < text.length && !isCliEnd(text.charCodeAt(j))) j += 1;
  if (j <= i) return null;
  return { start: i, end: j, value: text.slice(i, j) };
}

function looksSecret(value: string): boolean {
  if (value.length < 4 || value.length > 256) return false;
  if (value === "YES" || value === "NO" || value === "true" || value === "false") {
    return false;
  }
  // Birth-date passwords: `mysql -p1987-05-03` (digits + hyphens only).
  if (isBareDateOrTime(value)) return true;
  // Need some complexity: letter + digit/symbol, or long token
  let hasLetter = false;
  let hasOther = false;
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) hasLetter = true;
    else hasOther = true;
  }
  return hasLetter && (hasOther || value.length >= 8);
}

function isCliEnd(code: number): boolean {
  return (
    code === 32 ||
    code === 9 ||
    code === 10 ||
    code === 13 ||
    code === 34 ||
    code === 39 ||
    code === 59 ||
    code === 38 || // &
    code === 124 || // |
    code === 60 ||
    code === 62
  );
}

function isIdent(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 95
  );
}

function isSecretStart(code: number): boolean {
  return code > 32 && code !== 45; // not space, not another flag
}
