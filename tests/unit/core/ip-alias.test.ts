import { describe, expect, it } from "vitest";
import { classifyIpv4, createAliasFactory } from "../../../src/core/index";

describe("IPv4 class-preserving aliases", () => {
  it("classifies RFC 1918 / 5737 / public", () => {
    expect(classifyIpv4("172.16.42.10")).toBe("private_172");
    expect(classifyIpv4("10.1.2.3")).toBe("private_10");
    expect(classifyIpv4("192.168.1.10")).toBe("private_192");
    expect(classifyIpv4("198.51.100.12")).toBe("documentation");
    expect(classifyIpv4("82.124.45.199")).toBe("public");
    expect(classifyIpv4("127.0.0.1")).toBe("loopback");
  });

  it("keeps private and public distinguishable", () => {
    const factory = createAliasFactory({
      ipStyle: "preserveClass",
      geoMode: "mask",
      geoRoundDecimals: 2,
    });

    const internal = factory.aliasFor("ipv4", "172.16.42.10", "172.16.42.10");
    const attacker = factory.aliasFor("ipv4", "198.51.100.12", "198.51.100.12");
    const publicIp = factory.aliasFor("ipv4", "82.124.45.199", "82.124.45.199");

    expect(internal.startsWith("172.")).toBe(true);
    expect(classifyIpv4(internal)).toBe("private_172");

    expect(classifyIpv4(attacker)).toBe("documentation");
    expect(classifyIpv4(publicIp)).toBe("documentation");
    expect(attacker).not.toBe(publicIp);
  });
});
