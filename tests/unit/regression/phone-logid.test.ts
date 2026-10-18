import { describe, expect, it } from "vitest";
import { analyzeText, redactText } from "../../../src/core/index";

describe("phone vs logid false positives", () => {
  it("does not treat Fortinet-style 10-digit logids as phones", () => {
    const input =
      'logid="0316013056" eventid=0101039424 other=0100032002 ref=0419016384';
    const findings = analyzeText(input).findings.filter((f) => f.kind === "phone");
    expect(findings).toHaveLength(0);
    expect(redactText(input).apply.output).toContain("0316013056");
    expect(redactText(input).apply.output).toContain("0101039424");
  });

  it("still redacts compact FR mobiles 06/07 and separated landlines", () => {
    expect(analyzeText("call 0612345678 now").findings.some((f) => f.kind === "phone")).toBe(
      true,
    );
    expect(analyzeText("call 01 23 45 67 89 now").findings.some((f) => f.kind === "phone")).toBe(
      true,
    );
    expect(analyzeText("call 0123456789 now").findings.some((f) => f.kind === "phone")).toBe(
      false,
    );
  });

  it("keeps labeled phone fields even for landline-shaped values", () => {
    const r = analyzeText("phone: 0123456789");
    expect(r.findings.some((f) => f.kind === "phone" && f.value === "0123456789")).toBe(true);
  });
});
