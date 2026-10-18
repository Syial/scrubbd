import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyIpv4, redactText } from "../../../src/core/index";

const sshd = readFileSync(
  resolve(__dirname, "../../fixtures/wazuh-sshd.json"),
  "utf8",
);

describe("Wazuh sample redaction", () => {
  it("redacts systemname and preserves private vs documentation IPs", () => {
    const { analyze, apply, verify } = redactText(sshd);

    expect(analyze.mappings.some((m) => m.original === "ubuntu-server")).toBe(
      true,
    );
    expect(analyze.mappings.find((m) => m.original === "ubuntu-server")?.kind).toBe(
      "hostname",
    );

    const agentIp = analyze.mappings.find((m) => m.original === "172.16.42.10");
    const srcIp = analyze.mappings.find((m) => m.original === "198.51.100.12");
    expect(agentIp).toBeDefined();
    expect(srcIp).toBeDefined();
    expect(classifyIpv4(agentIp!.alias)).toBe("private_172");
    expect(classifyIpv4(srcIp!.alias)).toBe("documentation");

    expect(apply.output).toContain("compte-01");
    expect(apply.output).toContain("hote-01");
    expect(apply.output).not.toContain("thomas.dubois");
    expect(apply.output).not.toContain("ubuntu-server");
    expect(apply.output).toContain('"id": "004"');
    expect(apply.output).toContain("SSHD authentication success.");
    expect(verify.remaining).toHaveLength(0);
  });
});
