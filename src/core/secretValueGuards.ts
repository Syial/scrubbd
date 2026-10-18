/** Guards for values after password= / token= (empty fields vs glued secrets). */

/** Neighbor field names often swallowed after an empty secret assign. */
const BORROWED_FIELD_KEY =
  /^(status|from|user|username|user_name|host|hostname|duration|port|code|type|name|label|method|path|proto|protocol|src|dst|source|dest|ip|addr|time|date|ok|to|via|with|for|id|uid|gid|pid|tid|size|len|ttl|reason|result|action|event|level|msg|message|server|login|account|attempts|policy|link)$/i;

/** True when value looks like a borrowed next field (status=200), not a glued secret. */
export function isBorrowedFieldValue(value: string): boolean {
  const eq = value.indexOf("=");
  if (eq > 0) {
    const key = value.slice(0, eq);
    if (/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key) && BORROWED_FIELD_KEY.test(key)) {
      return true;
    }
  }
  return false;
}

/** Bare ISO date / clock token (no suffix). */
export function isBareDateOrTime(value: string): boolean {
  if (/^\d{4}-\d{2}-\d{2}(?:[T\s]|$)/.test(value)) return true;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value)) return true;
  if (/^\d{1,2}:\d{2}(:\d{2})?(?:\.\d+)?Z?$/.test(value)) return true;
  return false;
}

/** Reject spaced date/time after password: (ambiguous empty field). */
export function shouldRejectSecretValue(
  value: string,
  skippedSpacesBeforeValue: boolean,
): boolean {
  const v = value.replace(/[):.;,!?]+$/g, "");
  if (!v || v.length < 4) return true;
  if (/^(YES|NO|TRUE|FALSE|ON|OFF|OK)$/i.test(v)) return true;
  if (/^(chauthtok|auth|account|session|password)$/i.test(v)) return true;
  if (
    /^(server|host|hostname|user|username|login|reason|status|attempts|policy|link|type|name|label|from)$/i.test(
      v,
    )
  ) {
    return true;
  }
  if (skippedSpacesBeforeValue) {
    if (isBorrowedFieldValue(v)) return true;
    // Ambiguous empty field + date/time - leave the token; do not detect.
    if (isBareDateOrTime(v)) return true;
  }
  return false;
}

/** True when a date/time is a syslog stamp (unless also assigned as password). */
export function isLogTimestampContext(
  text: string,
  start: number,
  end: number,
): boolean {
  const token = text.slice(start, end);
  let atTimestamp = false;
  if (/^\d{4}-\d{2}-\d{2}$/.test(token)) {
    atTimestamp = /^ \d{2}:\d{2}/.test(text.slice(end, end + 6));
  } else if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(token)) {
    atTimestamp =
      start >= 11 && /^\d{4}-\d{2}-\d{2} $/.test(text.slice(start - 11, start));
  }
  if (!atTimestamp) return false;

  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const lineEnd = text.indexOf("\n", start);
  const line = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const assignOnLine = new RegExp(
    `(?:password|passwd|pwd|secret|token|passphrase)[ \\t]*[:=][ \\t]*["']?${escaped}`,
    "i",
  );
  // Password on this line equals the stamp → allow replacing the stamp too.
  if (assignOnLine.test(line)) return false;
  return true;
}
