import { foldCase } from "../fold";
import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";

/** Account hints from paths (/home/X, C:\Users\X, ~X). Use decoded text. */
export function findPathAccounts(text: string): Finding[] {
  return [
    ...findUnixHome(text),
    ...findWindowsUsers(text),
    ...findUncHomes(text),
    ...findTildeUser(text),
    ...findMailSpool(text),
  ];
}

/** `/var/mail/ines.carvalho` / `/var/spool/mail/x` */
function findMailSpool(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\/(?:var\/(?:spool\/)?mail|mailbox)\/([A-Za-z][A-Za-z0-9._+-]{1,64})\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (!isRedactableAccount(value)) continue;
    const start = m.index + m[0]!.indexOf(value);
    out.push({
      kind: "account",
      value,
      key: value.toLowerCase(),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function pushAccount(
  out: Finding[],
  text: string,
  start: number,
  end: number,
): void {
  const value = text.slice(start, end);
  if (!isRedactableAccount(value)) return;
  out.push({
    kind: "account",
    value,
    key: value.toLowerCase(),
    span: { start, end },
    decision: "replace",
  });
}

function findUnixHome(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  for (const prefix of ["/home/", "/users/"]) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(prefix, from);
      if (idx === -1) break;
      const start = idx + prefix.length;
      let i = start;
      while (i < text.length && isAccountChar(text.charCodeAt(i))) i += 1;
      if (i > start) pushAccount(out, text, start, i);
      from = Math.max(i, idx + prefix.length);
    }
  }
  return out;
}

function findWindowsUsers(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  // C:\Users\X or C:/Users/X
  let from = 0;
  while (from < text.length) {
    const idx = lower.indexOf("users", from);
    if (idx === -1) break;
    // look back for drive:\ or drive:/
    if (idx >= 3) {
      const drive = text.charCodeAt(idx - 3);
      const colon = text.charCodeAt(idx - 2);
      const sep = text.charCodeAt(idx - 1);
      const after = text.charCodeAt(idx + 5);
      if (
        isLetter(drive) &&
        colon === 58 &&
        (sep === 92 || sep === 47) &&
        (after === 92 || after === 47)
      ) {
        const start = idx + 6;
        let i = start;
        while (i < text.length && isAccountChar(text.charCodeAt(i))) i += 1;
        if (i > start) pushAccount(out, text, start, i);
        from = Math.max(i, idx + 5);
        continue;
      }
    }
    from = idx + 5;
  }
  return out;
}

function findUncHomes(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  for (const share of ["\\homes\\", "/homes/", "\\users\\", "/users/"]) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(share, from);
      if (idx === -1) break;
      const start = idx + share.length;
      let i = start;
      while (i < text.length && isAccountChar(text.charCodeAt(i))) i += 1;
      if (i > start) pushAccount(out, text, start, i);
      from = Math.max(i, idx + share.length);
    }
  }
  return out;
}

function findTildeUser(text: string): Finding[] {
  const out: Finding[] = [];
  let i = 0;
  while (i < text.length) {
    if (text.charCodeAt(i) !== 126 /* ~ */) {
      i += 1;
      continue;
    }
    const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
    if (isAccountChar(prev) || isLetter(prev)) {
      i += 1;
      continue;
    }
    const start = i + 1;
    let j = start;
    while (j < text.length && isAccountChar(text.charCodeAt(j))) j += 1;
    if (j > start) pushAccount(out, text, start, j);
    i = Math.max(j, i + 1);
  }
  return out;
}

function isAccountChar(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 46 ||
    code === 95 ||
    code === 45 ||
    (code >= 192 && code <= 255)
  );
}

function isLetter(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122)
  );
}
