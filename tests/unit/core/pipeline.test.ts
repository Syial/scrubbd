import { describe, expect, it } from "vitest";
import { analyzeText, applyMappings, verifyOutput } from "../../../src/core/index";
import type { MappingEntry } from "../../../src/core/types";

describe("pipeline", () => {
  it("maps the same IP to one coherent alias", () => {
    const input = "a=10.0.0.1 b=10.0.0.1 c=10.0.0.2";
    const analyzed = analyzeText(input);
    expect(analyzed.mappings).toHaveLength(2);

    const first = analyzed.mappings.find((m) => m.original === "10.0.0.1");
    const second = analyzed.mappings.find((m) => m.original === "10.0.0.2");
    expect(first?.alias.startsWith("10.")).toBe(true);
    expect(second?.alias.startsWith("10.")).toBe(true);
    expect(first?.alias).not.toBe(second?.alias);
    expect(first?.alias).not.toBe("10.0.0.1");

    const applied = applyMappings(input, analyzed.mappings);
    expect(applied.output).toBe(`a=${first!.alias} b=${first!.alias} c=${second!.alias}`);
  });

  it("reports leftovers when a mapping was not applied", () => {
    const input = "ip=10.0.0.8";
    const analyzed = analyzeText(input);
    const broken = analyzed.mappings.map((entry) => ({
      ...entry,
      alias: "10.255.255.1",
      decision: "replace" as const,
    }));
    const verify = verifyOutput(input, broken);
    expect(verify.remaining.length).toBeGreaterThan(0);
  });

    /** Single-pass apply must not corrupt an alias that equals another original. */
  it("does not corrupt an IP alias that equals another mapped original", () => {
    const input = "src=172.18.48.15 dst=172.30.186.243";
    const mappings: MappingEntry[] = [
      {
        kind: "ipv4",
        original: "172.18.48.15",
        alias: "172.30.186.243",
        decision: "replace",
        occurrenceCount: 1,
      },
      {
        kind: "ipv4",
        original: "172.30.186.243",
        alias: "192.0.2.50",
        decision: "replace",
        occurrenceCount: 1,
      },
    ];
    const applied = applyMappings(input, mappings);
    expect(applied.output).toBe("src=172.30.186.243 dst=192.0.2.50");
    expect(applied.output).not.toContain("24375");
    expect(applied.output).not.toMatch(/src=192\.0\.2\.50/);
  });
});
