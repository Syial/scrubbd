/** Map a decoded JSON string span back into the encoded source literal. */
export function mapDecodedSpanToEncoded(
  encoded: string,
  decodedSpan: { start: number; end: number },
): { start: number; end: number } | null {
  if (decodedSpan.start < 0 || decodedSpan.end < decodedSpan.start) return null;

  let enc = 0;
  let dec = 0;
  let srcStart = -1;
  let srcEnd = -1;

  while (enc <= encoded.length && dec <= decodedSpan.end) {
    if (dec === decodedSpan.start && srcStart === -1) srcStart = enc;
    if (dec === decodedSpan.end) {
      srcEnd = enc;
      break;
    }
    if (enc >= encoded.length) break;

    if (encoded.charCodeAt(enc) === 92 /* \ */) {
      const step = readEscape(encoded, enc);
      if (!step) return null;
      enc = step.nextEnc;
      dec += step.decodedUnits;
      continue;
    }

    enc += 1;
    dec += 1;
  }

  if (srcStart === -1 || srcEnd === -1) return null;
  return { start: srcStart, end: srcEnd };
}

function readEscape(
  encoded: string,
  enc: number,
): { nextEnc: number; decodedUnits: number } | null {
  if (enc + 1 >= encoded.length) return null;
  const marker = encoded.charCodeAt(enc + 1);

  // \uXXXX
  if (marker === 117 /* u */ && enc + 5 < encoded.length) {
    for (let i = 2; i <= 5; i += 1) {
      if (!isHex(encoded.charCodeAt(enc + i))) return null;
    }
    return { nextEnc: enc + 6, decodedUnits: 1 };
  }

  // \", \\, \/, \b, \f, \n, \r, \t
  if (
    marker === 34 ||
    marker === 92 ||
    marker === 47 ||
    marker === 98 ||
    marker === 102 ||
    marker === 110 ||
    marker === 114 ||
    marker === 116
  ) {
    return { nextEnc: enc + 2, decodedUnits: 1 };
  }

  return null;
}

function isHex(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  );
}
