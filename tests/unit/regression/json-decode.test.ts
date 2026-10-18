import { describe, expect, it } from "vitest";
import { redactText } from "../../../src/core/index";

describe("JSON string decode before detect", () => {
  it("replaces Account Name after JSON \\t escapes in full_log", () => {
    const input = JSON.stringify({
      full_log: "Account Name:\t\tefontaine\r\nAccount Domain:\t\tFAKECORP",
      data: { win: { eventdata: { targetUserName: "efontaine" } } },
    });
    const { apply } = redactText(input);
    expect(apply.output).not.toContain("efontaine");
    expect(apply.output).toContain("compte-");
    JSON.parse(apply.output); // still valid JSON
  });

  it("redacts emails and names written with \\uXXXX escapes", () => {
    const input = `{"nom":"\\u00c9lodie Fontaine","email":"elodie.fontaine\\u0040fakecorp.org","latitude":48.8698}`;
    const { apply } = redactText(input);
    expect(apply.output).not.toMatch(/\\u00c9lodie/i);
    expect(apply.output).not.toMatch(/\\u0040fakecorp/i);
    expect(apply.output).toContain("personne-");
    expect(apply.output).toContain("compte-");
    expect(apply.output).toContain("@domaine-");
    const parsed = JSON.parse(apply.output) as { latitude: number };
    expect(typeof parsed.latitude).toBe("number");
  });
});
