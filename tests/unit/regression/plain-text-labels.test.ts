import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, redactText } from "../../../src/core/index";
import { findLabeledValues } from "../../../src/core/textLabels";

const fixture = readFileSync(
  resolve(__dirname, "../../fixtures/app-text.log"),
  "utf8",
);

describe("plain-text labeled fields", () => {
  it("extracts key: value pairs and user speech names", () => {
    const labels = findLabeledValues(fixture);
    const values = labels.map((l) => [l.fieldName.toLowerCase(), l.value] as const);

    expect(values).toContainEqual(["email", "jean.dupont@example.com"]);
    expect(values).toContainEqual(["phone", "+33 6 1234 5678"]);
    expect(values).toContainEqual(["username", "admin_test"]);
    expect(values).toContainEqual(["address", "12 Rue de la Paix, 75002 Paris"]);
    expect(values).toContainEqual(["account", "sophie.lefevre@example.org"]);
    expect(values).toContainEqual(["user", "Jean Dupont"]);
    expect(values).toContainEqual(["user", "Alice Martin"]);
    expect(values).toContainEqual(["user", "Thomas Durand"]);
  });

  it("redacts phones, people, addresses and accounts in free-text logs", () => {
    const { analyze, apply, verify } = redactText(fixture);

    expect(analyze.summary.byKind.phone).toBeGreaterThanOrEqual(1);
    expect(analyze.summary.byKind.person_name).toBeGreaterThanOrEqual(2);
    expect(analyze.summary.byKind.address).toBe(1);
    expect(analyze.summary.byKind.account).toBeGreaterThanOrEqual(1);
    expect(analyze.summary.byKind.email).toBeGreaterThanOrEqual(3);

    expect(apply.output).not.toContain("jean.dupont@example.com");
    expect(apply.output).not.toContain("+33 6 1234 5678");
    expect(apply.output).not.toContain("Jean Dupont");
    expect(apply.output).not.toContain("Alice Martin");
    expect(apply.output).not.toContain("12 Rue de la Paix, 75002 Paris");
    expect(apply.output).not.toContain("admin_test");
    expect(apply.output).toContain("[TEL-01]");
    expect(apply.output).toContain("[ADR-01]");
    expect(apply.output).toContain("personne-");
    expect(apply.output).toContain("compte-01@domaine-01.example");

    // Timestamps with -0400 must not become phones.
    expect(apply.output).toContain("10:15:32-0400");
    // Bare surname in SQL without a classified field may remain (known limit).
    expect(verify.remaining).toHaveLength(0);
  });

  it("does not invent phones from timezone offsets in plain text", () => {
    expect(analyzeText("ts=2023-10-24 10:15:32-0400 ok").findings).toHaveLength(0);
  });
});
