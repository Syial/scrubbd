import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, redactText } from "../../../src/core/index";

describe("regression: known false positives from generic tools", () => {
  it("does not treat +0000 timezone as a phone or IP", () => {
    const input = "2025-01-02T12:00:00+0000 event=login";
    const result = analyzeText(input);
    expect(result.findings.filter((f) => f.kind === "phone" || f.kind === "ipv4")).toHaveLength(
      0,
    );
  });

  it("does not rewrite a plain date as a finding", () => {
    const input = "event_date=2025-01-02";
    expect(analyzeText(input).findings).toHaveLength(0);
  });

  it("keeps a real IP intact as one value (not zip/card fragments)", () => {
    const input = "src=192.168.1.10";
    const result = analyzeText(input);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.value).toBe("192.168.1.10");
    expect(result.mappings[0]?.alias.startsWith("192.168.")).toBe(true);
  });

  it("redacts Luhn-valid issuer cards, ignores non-Luhn digit runs", () => {
    const card = analyzeText("ref=4111111111111111");
    expect(card.findings).toHaveLength(1);
    expect(card.findings[0]?.kind).toBe("secret");
    expect(card.mappings[0]?.alias).toBe("[SECRET]");

    const junk = analyzeText("ref=4111111111111112");
    expect(junk.findings.filter((f) => f.kind === "secret")).toHaveLength(0);
  });

  it("does not treat OS version numbers as IPv4", () => {
    const input = "fileVersion=10.0.19045.5555";
    const result = analyzeText(input);
    expect(result.findings.filter((f) => f.kind === "ipv4")).toHaveLength(0);
  });

  it("still produces a summary for unstructured text", () => {
    const sample = readFileSync(
      resolve(__dirname, "../../fixtures/sample.txt"),
      "utf8",
    );
    const { analyze, apply } = redactText(sample);
    expect(analyze.summary.format).toBe("text");
    expect(analyze.summary.uniqueValues).toBeGreaterThan(0);
    expect(apply.output).toContain("127.0.0.1");
    expect(apply.output).toContain("10.0.19045.5555");
    // Private lab IP stays in a private range.
    expect(apply.output).toMatch(/\b10\.\d+\.\d+\.\d+\b/);
  });
});
