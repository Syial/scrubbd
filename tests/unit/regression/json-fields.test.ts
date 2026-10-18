import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  analyzeText,
  redactText,
  DEFAULT_REDACT_OPTIONS,
} from "../../../src/core/index";

const fixture = readFileSync(
  resolve(__dirname, "../../fixtures/app-events.json"),
  "utf8",
);

describe("JSON field rules integration", () => {
  it("detects structured PII with path-aware kinds", () => {
    const result = analyzeText(fixture);
    expect(result.format).toBe("json");

    const byKind = result.summary.byKind;
    expect(byKind.ipv4).toBe(2);
    expect(byKind.email).toBe(2);
    expect(byKind.phone).toBe(1);
    expect(byKind.person_name).toBe(2);
    expect(byKind.address).toBe(1);
    expect(byKind.geo).toBe(2);
    expect(byKind.internal_id).toBe(2); // user_id, device_id
    expect(byKind.business_id).toBe(1); // invoice_id

    const originals = new Set(result.mappings.map((m) => m.original));
    expect(originals.has("42 Rue de la Paix, 75002 Paris")).toBe(true);
    expect(originals.has("usr_94810a7b")).toBe(true);
    expect(originals.has("INV-2026-8941")).toBe(true);
    expect(originals.has("Lyon")).toBe(false);
    expect(originals.has("amount_usd")).toBe(false);
  });

  it("uses disjoint alias families", () => {
    const { analyze, apply, verify } = redactText(fixture);

    for (const person of analyze.mappings.filter((m) => m.kind === "person_name")) {
      expect(person.alias).toMatch(/^personne-\d+$/);
    }
    for (const email of analyze.mappings.filter((m) => m.kind === "email")) {
      expect(email.alias).toMatch(/^compte-\d+@domaine-\d+\.example$/);
      for (const person of analyze.mappings.filter((m) => m.kind === "person_name")) {
        expect(email.alias.startsWith(person.alias)).toBe(false);
      }
    }

    expect(apply.output).toContain("[ADR-01]");
    // Numeric geo stays a JSON number (0), never [GEO-01].
    expect(apply.output).toMatch(/"latitude":\s*0/);

    expect(apply.output).toContain("usr_94810a7b");
    expect(apply.output).toContain("INV-2026-8941");
    expect(apply.output).toContain("2026-10-11T14:32:01.089Z");
    // Public IPs land in documentation ranges, not opaque labels.
    expect(apply.output).toMatch(/192\.0\.2\.|198\.51\.100\.|203\.0\.113\./);
    expect(verify.remaining).toHaveLength(0);
  });

  it("can round geo and redact id families when opted in", () => {
    const { apply, analyze } = redactText(fixture, {
      ...DEFAULT_REDACT_OPTIONS,
      redactInternalIds: true,
      redactBusinessIds: true,
      alias: {
        ...DEFAULT_REDACT_OPTIONS.alias,
        geoMode: "round",
        geoRoundDecimals: 2,
      },
    });

    expect(analyze.mappings.find((m) => m.original === "45.764043")?.alias).toBe(
      "45.76",
    );
    expect(apply.output).not.toContain("usr_94810a7b");
    expect(apply.output).not.toContain("INV-2026-8941");
    expect(apply.output).toContain("[ID-01]");
    expect(apply.output).toContain("[BIZ-01]");
  });

  it("classifies Wazuh-style camelCase account fields", () => {
    const input = JSON.stringify({
      data: {
        win: {
          eventdata: {
            targetUserName: "DOMAIN\\alice",
            ipAddress: "10.0.0.8",
            workstationName: "PC-ALICE",
          },
        },
      },
      agent: { name: "wazuh-agent-01", id: "001" },
    });
    const result = analyzeText(input);
    const kinds = new Map(result.mappings.map((m) => [m.original, m.kind]));
    expect(kinds.get("alice")).toBe("account");

    expect(kinds.get("10.0.0.8")).toBe("ipv4");
    expect(kinds.get("PC-ALICE")).toBe("hostname");
    expect(kinds.get("wazuh-agent-01")).toBe("hostname");
    expect(kinds.has("001")).toBe(false);
  });

  it("does not treat timezone +0000 as a phone in plain text", () => {
    expect(analyzeText("timestamp=2025-01-02T12:00:00+0000").findings).toHaveLength(
      0,
    );
  });

  it("detects e-mails in plain text without JSON fields", () => {
    const result = analyzeText("contact me at ada.lovelace@example.org thanks");
    expect(result.mappings).toHaveLength(1);
    expect(result.mappings[0]?.alias).toBe("compte-01@domaine-01.example");
  });
});
