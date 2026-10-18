import { describe, expect, it } from "vitest";
import {
  LEAF_RULES,
  PATH_RULES,
  classifyField,
  classifyFieldName,
  isIpv4ExcludedField,
  isProtectedField,
  normalizeFieldName,
  type LeafRule,
} from "../../../src/rules/fieldRules";

/** Verdict summary for test tables. */
function summary(path: string | readonly string[]): string {
  const verdict = classifyField(typeof path === "string" ? [path] : path);
  if (verdict === null) return "none";
  switch (verdict.type) {
    case "detect":
      return verdict.kind;
    case "ambiguous":
      return `ambiguous→${verdict.fallback}`;
    case "protected":
      return "protected";
  }
}

describe("normalizeFieldName", () => {
  const cases: Array<[string, string]> = [
    ["userId", "user_id"],
    ["UserID", "user_id"],
    ["user_ID", "user_id"],
    ["targetUserName", "target_user_name"],
    ["IPAddress", "ip_address"],
    ["ip-address", "ip_address"],
    ["IP.Address", "ip_address"],
    ["IPv4Address", "ipv4_address"],
    ["clientIPv4", "client_ipv4"],
    ["e-mail", "e_mail"],
    ["eMail", "e_mail"],
    ["@timestamp", "timestamp"],
    ["téléphone", "telephone"],
    ["XMLHttpRequest", "xml_http_request"],
    ["__x__", "x"],
    ["address1", "address1"],
  ];
  it.each(cases)("%s → %s", (raw, expected) => {
    expect(normalizeFieldName(raw)).toBe(expected);
  });

  it("ignores oversized keys", () => {
    expect(normalizeFieldName("A".repeat(200))).toBe("");
  });
});

describe("style equivalence", () => {
  it.each(["ipAddress", "ip_address", "ip-address", "IP.Address", "IPAddress"])(
    "%s is classified as ip",
    (name) => {
      expect(summary(name)).toBe("ip");
    },
  );
});

describe("detect by name", () => {
  const cases: Array<[string, string]> = [
    ["targetUserName", "account"],
    ["subjectUserName", "account"],
    ["attempted_username", "account"],
    ["workstationName", "hostname"],
    ["systemname", "hostname"],
    ["devname", "hostname"],
    ["srcname", "hostname"],
    ["dstname", "hostname"],
    ["nom", "person_name"],
    ["prenom", "person_name"],
    ["system_name", "hostname"],
    ["computername", "hostname"],
    ["serverName", "hostname"],
    ["computer", "hostname"],
    ["e-mail", "email"],
    ["Email", "email"],
    ["phone", "phone"],
    ["customer_name", "person_name"],
    ["full_name", "person_name"],
    ["user_id", "internal_id"],
    ["deviceId", "internal_id"],
    ["invoice_id", "business_id"],
    ["latitude", "geo"],
    ["mac_address", "mac"],
    ["srcip", "ip"],
    ["remote_addr", "ip"],
    ["billing_address", "address"],
    ["zip_code", "address"],
    ["date_of_birth", "birth_date"],
    ["password", "secret"],
    ["authToken", "secret"],
    ["AWS_SECRET_ACCESS_KEY", "secret"],
    ["secretAccessKey", "secret"],
    ["password_hash", "secret"],
  ];
  it.each(cases)("%s → %s", (name, expected) => {
    expect(summary(name)).toBe(expected);
  });
});

describe("protected fields", () => {
  it.each([
    "is_mobile",
    "has_email",
    "email_verified",
    "timestamp",
    "created_at",
    "login_time",
    "file_version",
    "agentVersion",
    "sha256",
    "trace_id",
    "amount_usd",
    "status_code",
    "src_port",
    "elevatedToken",
    "logid",
    "log_id",
    "tokenElevationType",
  ])("%s is protected", (name) => {
    expect(summary(name)).toBe("protected");
    expect(isProtectedField([name])).toBe(true);
  });
});

describe("no rule", () => {
  it.each([
    "user_agent",
    "service",
    "event",
    "city",
    "country",
    "conversion",
    "failure_reason",
    "masked_card",
    "level",
    "name",
  ])("%s → no verdict", (name) => {
    expect(classifyField([name])).toBeNull();
  });

  it("`agent.id` is not sensitive", () => {
    expect(classifyField(["agent", "id"])).toBeNull();
  });
});

describe("ambiguous names: value decides", () => {
  it.each([
    ["address", "ambiguous→address"],
    ["remote_address", "ambiguous→address"],
    ["host", "ambiguous→hostname"],
    ["ssh_host", "ambiguous→hostname"],
  ])("%s → %s", (name, expected) => {
    expect(summary(name)).toBe(expected);
  });

  it("exposes candidates", () => {
    const verdict = classifyField(["address"]);
    expect(verdict?.type).toBe("ambiguous");
    if (verdict?.type === "ambiguous") {
      expect(verdict.candidates).toEqual(["ip", "mac", "address"]);
    }
  });
});

describe("path rules", () => {
  const cases: Array<[readonly string[], string]> = [
    [["agent", "name"], "hostname"],
    [["manager", "name"], "hostname"],
    [["user", "name"], "account"],
    [["process", "user", "name"], "account"],
    [["host", "name"], "hostname"],
    [["name"], "none"],
    [["rule", "description"], "protected"],
    [["rule", "mitre", "id"], "protected"],
    [["decoder", "name"], "protected"],
    [["agent.name"], "hostname"],
    [["rule.description"], "protected"],
    [["data", "win", "eventdata", "targetUserName"], "account"],
    [["data", "srcip"], "ip"],
    [["agent", "ip"], "ip"],
    // Bare `name` stays neutral; under a person parent it is person_name
    [["data", "contacts", "name"], "person_name"],
    [["customer", "name"], "person_name"],
    [["data", "name"], "none"],
    // Parent can resolve an ambiguous leaf like `address`
    [["IP", "Address"], "ip"],
    [["mac", "address"], "mac"],
    [["billing", "address"], "address"],
    [["mac.address"], "mac"],
    // Uninformative parent: ambiguity stays; value must decide
    [["foo", "address"], "ambiguous→address"],
  ];
  it.each(cases)("%j → %s", (path, expected) => {
    expect(summary(path)).toBe(expected);
  });
});

describe("robustness", () => {
  it("stays correct after cache saturation", () => {
    for (let i = 0; i < 10_000; i++) classifyField([`champ_inconnu_${i}`]);
    expect(summary("email")).toBe("email");
    expect(summary("targetUserName")).toBe("account");
  });

  it("ignores oversized key names", () => {
    expect(classifyField(["A".repeat(100_000)])).toBeNull();
  });

  it("handles an empty path", () => {
    expect(classifyField([])).toBeNull();
  });
});

describe("legacy API compatibility", () => {
  it("classifyFieldName", () => {
    expect(classifyFieldName("email")).toBe("email");
    expect(classifyFieldName("remote_address")).toBe("address");
    expect(classifyFieldName("version")).toBeNull();
  });

  it("isIpv4ExcludedField", () => {
    expect(isIpv4ExcludedField("fileVersion")).toBe(true);
    expect(isIpv4ExcludedField("conversion")).toBe(false);
    expect(isIpv4ExcludedField("ip_address")).toBe(false);
  });
});

describe("rule table integrity", () => {
  const namesOf = (rule: LeafRule): string[] => [
    ...(rule.names.exact ?? []),
    ...(rule.names.prefix ?? []),
    ...(rule.names.suffix ?? []),
  ];

  it("all table names are already normalized", () => {
    const leafIssues = LEAF_RULES.flatMap((rule) =>
      namesOf(rule)
        .filter((name) => normalizeFieldName(name) !== name)
        .map((name) => `${rule.id}: ${name}`),
    );
    const pathIssues = PATH_RULES.flatMap((rule) =>
      rule.path
        .filter((segment) => normalizeFieldName(segment) !== segment)
        .map((segment) => `${rule.id}: ${segment}`),
    );
    expect([...leafIssues, ...pathIssues]).toEqual([]);
  });

  it("rule ids are unique", () => {
    const ids = [...LEAF_RULES.map((rule) => rule.id), ...PATH_RULES.map((rule) => rule.id)];
    expect(ids.filter((id, index) => ids.indexOf(id) !== index)).toEqual([]);
  });

  it("no exact name appears in two rules (later would be shadowed)", () => {
    const seen = new Map<string, string>();
    const duplicates: string[] = [];
    for (const rule of LEAF_RULES) {
      for (const name of rule.names.exact ?? []) {
        const owner = seen.get(name);
        if (owner !== undefined && owner !== rule.id) duplicates.push(`${name}: ${owner} / ${rule.id}`);
        seen.set(name, rule.id);
      }
    }
    expect(duplicates).toEqual([]);
  });
});
