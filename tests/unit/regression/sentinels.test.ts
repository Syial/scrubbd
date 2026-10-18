import { describe, expect, it } from "vitest";
import { analyzeText, redactText } from "../../../src/core/index";

describe("sentinel values must never be redacted", () => {
  it("does not treat bare '-' as an account", () => {
    const input = JSON.stringify({
      rule: { description: "Logon Failure - Unknown user or bad password" },
      data: {
        win: {
          eventdata: {
            subjectUserName: "-",
            ipAddress: "-",
            ipPort: "-",
            targetUserName: "efontaine",
          },
        },
      },
    });
    const { analyze, apply } = redactText(input);
    expect(analyze.mappings.some((m) => m.original === "-" && m.decision === "replace")).toBe(
      false,
    );
    expect(apply.output).toContain("Logon Failure - Unknown");
    expect(apply.output).toContain('"ipAddress":"-"');
    expect(apply.output).toContain('"subjectUserName":"-"');
    expect(apply.output).not.toContain("efontaine");
  });

  it("does not turn Program Files paths into DOMAIN\\user accounts", () => {
    const decoded = String.raw`C:\Program Files\Mozilla Firefox\firefox.exe`;
    const input = JSON.stringify({ commandLine: decoded });
    const out = redactText(input).apply.output;
    expect(out).toContain("Mozilla Firefox");
    expect(out).toContain("firefox.exe");
    expect(out).not.toMatch(/compte-\d+ Firefox/);
  });

  it("keeps Bearer and only redacts the token", () => {
    const input = JSON.stringify({
      authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
    });
    const out = redactText(input).apply.output;
    expect(out).toContain("Bearer");
    expect(out).toContain("[SECRET]");
    expect(out.match(/\[SECRET\]/g)?.length).toBe(1);

    const cmdline = JSON.stringify({
      commandLine:
        // Prefix split on purpose: a literal GitHub-token shape trips secret scanners.
        `curl -H "Authorization: Bearer ${"ghp" + "_"}A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"`,
    });
    const out2 = redactText(cmdline).apply.output;
    expect(out2).toContain("Authorization: Bearer [SECRET]");
    expect(out2.match(/\[SECRET\]/g)?.length).toBe(1);
  });

  it("uses the same alias for DOMAIN\\user and bare user", () => {
    const input =
      "user=camille /user:FAKECORP\\camille Winter2026! subjectUserName=camille";
    const { analyze, apply } = redactText(input);
    const accounts = analyze.mappings.filter(
      (m) => m.kind === "account" && m.decision === "replace" && m.original === "camille",
    );
    expect(accounts.length).toBe(1);
    expect(accounts[0]?.alias).toMatch(/^compte-/);
    expect(accounts[0]?.occurrenceCount).toBeGreaterThanOrEqual(2);
    expect(apply.output).toContain("[SECRET]");
    expect(apply.output).not.toContain("Winter2026!");
    expect(apply.output).not.toContain("camille");
    // DOMAIN kept, user aliased once
    expect(apply.output).toContain("FAKECORP\\");
  });
});

describe("sentinel helper", () => {
  it("rejects empty-like values in analyze", () => {
    expect(analyzeText('user=-').findings).toHaveLength(0);
    expect(analyzeText('user=N/A').findings).toHaveLength(0);
  });
});
