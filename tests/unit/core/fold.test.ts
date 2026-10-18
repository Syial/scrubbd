import { describe, expect, it } from "vitest";
import { foldCase } from "../../../src/core/fold";
import { analyzeText, applyMappings } from "../../../src/core/pipeline";

const run = (input: string) => applyMappings(input, analyzeText(input).mappings).output;

describe("foldCase", () => {
  it("keeps length for every BMP code point (only U+0130 would change under toLowerCase)", () => {
    for (let cp = 0; cp <= 0xffff; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const s = String.fromCodePoint(cp);
      expect(foldCase(s).length).toBe(s.length);
    }
  });
});

describe("U+0130 (İ) does not shift replacements", () => {
  const pii = "user=lea.moreau mail lea.moreau@fakecorp.org ip 185.199.108.153";

  it("same values replaced with or without leading İ", () => {
    const base = run(`ÎÎÎÎ ${pii}`).replace(/^ÎÎÎÎ /, "");
    const turkish = run(`İİİİ ${pii}`).replace(/^İİİİ /, "");
    expect(turkish).toBe(base);
    expect(turkish).not.toContain("lea.moreau");
    expect(turkish).not.toContain("185.199.108.153");
  });

  it("NDJSON output stays valid JSON without cleartext PII", () => {
    const line = '{"name":"İbrahim","user":"lea.moreau","ip":"185.199.108.153","mail":"lea.moreau@fakecorp.org"}';
    const out = run(line);
    expect(() => JSON.parse(out)).not.toThrow();
    expect(out).not.toMatch(/lea\.moreau|185\.199\.108\.153/);
  });

  it("CSV keeps the same field count", () => {
    const csv = "id;nom;prenom;email;ip\n1;İpek;Yıldız;ipek.yildiz@example.org;185.199.108.153";
    const out = run(csv).split("\n");
    expect(out[1]!.split(";").length).toBe(5);
    expect(out[1]).not.toContain("185.199.108.153");
  });
});
