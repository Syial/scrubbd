import {
  classifyField,
  type FieldKind,
  type FieldVerdict,
} from "../rules/fieldRules";
import { isKeptAccount, isRedactableAccount } from "./accounts";
import {
  isAccountStopword,
  isHostnameStopword,
  isPersonNameStopword,
  looksLikePersonNamePhrase,
} from "./stopwords";
import { applyFast, scanExactSecretHits, scanMappedHits } from "./applyFast";
import { createAliasFactory } from "./alias";
import { findAuthAccounts } from "./detectors/authGrammar";
import { findCefFields } from "./detectors/cefFields";
import { findCliSecrets } from "./detectors/cliSecrets";
import { findCsvColumnValues } from "./detectors/csvColumns";
import { findEmails, isValidEmail } from "./detectors/email";
import { findEmailDerivedNames } from "./detectors/emailNames";
import { findHostsInText } from "./detectors/hostsInText";
import { findIpv4, isValidIpv4 } from "./detectors/ipv4";
import { findIpv6, normalizeIpv6 } from "./detectors/ipv6";
import { findMac, isValidMac } from "./detectors/mac";
import { findNginxCombinedUsers } from "./detectors/nginxCombined";
import { findSquidAccessUsers } from "./detectors/squidAccess";
import { findAuditFields } from "./detectors/auditFields";
import { findZeekColumnValues } from "./detectors/zeekColumns";
import { findQuotedSecrets } from "./detectors/quotedSecrets";
import { findDhcpHosts } from "./detectors/dhcpHosts";
import { findSqlValues } from "./detectors/sqlValues";
import { findPathAccounts } from "./detectors/pathAccounts";
import { findPathPersonNames } from "./detectors/pathPersonNames";
import { findPaymentIds } from "./detectors/payment";
import { findPhones, isPhoneValue } from "./detectors/phone";
import { findPhraseSecrets } from "./detectors/phraseSecrets";
import { findSecretAssignments } from "./detectors/secretAssign";
import { findSecrets } from "./detectors/secrets";
import { findSyslogHosts } from "./detectors/syslog";
import { findTextHints } from "./detectors/textHints";
import { findUrlAuth } from "./detectors/urlAuth";
import { findXmlFields } from "./detectors/xmlFields";
import {
  isGroupLikeCn,
  isKeptHostname,
  isMachineAccount,
  normalizeHostnameKey,
} from "./hostIdentity";
import { normalizePersonNameKey } from "./personName";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "./sentinels";
import { detectFormat } from "./format";
import { mapDecodedSpanToEncoded } from "./jsonStringSpans";
import { collectJsonLeaves, parseJsonDocument } from "./jsonTraverse";
import { findLabeledValues } from "./textLabels";
import type {
  AnalyzeResult,
  ApplyResult,
  Finding,
  FindingKind,
  LeakHit,
  MappingEntry,
  RedactOptions,
  VerifyResult,
} from "./types";
import { DEFAULT_REDACT_OPTIONS } from "./types";

export function analyzeText(
  input: string,
  options: RedactOptions = DEFAULT_REDACT_OPTIONS,
): AnalyzeResult {
  const format = detectFormat(input);
  const findings = collectFindings(input, format, options);
  const mappings = buildMappings(findings, options);

  const byKind: AnalyzeResult["summary"]["byKind"] = {};
  for (const finding of findings) {
    byKind[finding.kind] = (byKind[finding.kind] ?? 0) + 1;
  }

  return {
    format,
    findings,
    mappings,
    summary: {
      format,
      totalFindings: findings.length,
      uniqueValues: mappings.length,
      byKind,
    },
  };
}

export function applyMappings(input: string, mappings: MappingEntry[]): ApplyResult {
  const output = applyFast(input, mappings, needsSpanOnlyReplace, surfaceAlias);
  return { output, mappings };
}

/** Verify originals no longer appear as standalone tokens. */
export function verifyOutput(output: string, mappings: MappingEntry[]): VerifyResult {
  const remaining: LeakHit[] = [];
  const seen = new Set<string>();
  const push = (original: string, kind: MappingEntry["kind"], index: number) => {
    const id = `${kind}\0${original}\0${index}`;
    if (seen.has(id)) return;
    seen.add(id);
    remaining.push({ original, kind, index });
  };

  for (const hit of scanMappedHits(output, mappings, needsSpanOnlyReplace)) {
    push(hit.search, hit.kind, hit.start);
  }

  // Non-propagated secrets still in the output → warning (linear trie pass).
  const warnSecrets: string[] = [];
  for (const entry of mappings) {
    if (entry.decision !== "replace" || entry.kind !== "secret") continue;
    for (const form of [entry.original, ...(entry.variants ?? [])]) {
      if (form.length < 8) continue;
      if (WEAK_SECRET_WORDS.has(form.toLowerCase())) continue;
      if (isPropagatableSecret(form)) continue;
      warnSecrets.push(form);
    }
  }
  for (const hit of scanExactSecretHits(output, warnSecrets)) {
    push(hit.search, "secret", hit.start);
  }

  return { remaining };
}

export function redactText(
  input: string,
  options: RedactOptions = DEFAULT_REDACT_OPTIONS,
): { analyze: AnalyzeResult; apply: ApplyResult; verify: VerifyResult } {
  const analyze = analyzeText(input, options);
  const apply = applyMappings(input, analyze.mappings);
  const verify = verifyOutput(apply.output, analyze.mappings);
  return { analyze, apply, verify };
}

function collectFindings(
  input: string,
  format: ReturnType<typeof detectFormat>,
  options: RedactOptions,
): Finding[] {
  if (format === "json" || format === "jsonl") {
    const parsed = parseJsonDocument(input, format);
    if (parsed.ok) {
      const structured = findingsFromJson(input, parsed.documents, options);
      const loose = collectLooseFindings(input);
      return mergeNonOverlapping([...structured, ...loose]);
    }
  }

  // Plain text: CSV columns (header-aware), labeled pairs, then free-text detectors.
  const csv = findCsvColumnValues(input, options);
  const labeled = findingsFromTextLabels(input, options);
  const loose = collectLooseFindings(input);
  return mergeNonOverlapping([...csv, ...labeled, ...loose]);
}

function collectLooseFindings(input: string): Finding[] {
  return [
    ...findUrlAuth(input),
    ...findCliSecrets(input),
    ...findQuotedSecrets(input),
    ...findSecretAssignments(input),
    ...findPhraseSecrets(input),
    ...findSecrets(input),
    ...findZeekColumnValues(input),
    ...findPaymentIds(input),
    ...findXmlFields(input),
    ...findCefFields(input),
    ...findAuthAccounts(input),
    ...findPathAccounts(input),
    ...findPathPersonNames(input),
    ...findNginxCombinedUsers(input),
    ...findSquidAccessUsers(input),
    ...findAuditFields(input),
    ...findHostsInText(input),
    ...findDhcpHosts(input),
    ...findSqlValues(input),
    ...findSyslogHosts(input),
    ...findMac(input),
    ...findPhones(input),
    ...findIpv4(input),
    ...findIpv6(input),
    ...findEmails(input),
    ...findEmailDerivedNames(input),
    ...findTextHints(input),
  ];
}

function findingsFromTextLabels(input: string, options: RedactOptions): Finding[] {
  const findings: Finding[] = [];

  for (const label of findLabeledValues(input)) {
    const verdict = classifyField([label.fieldName]);
    if (verdict?.type === "protected") continue;

    if (
      (verdict?.type === "detect" && verdict.kind === "ip") ||
      (verdict?.type === "ambiguous" && verdict.candidates.includes("ip"))
    ) {
      const embedded = [...findIpv4(label.value), ...findIpv6(label.value)];
      if (embedded.length > 0) {
        for (const hit of embedded) {
          findings.push({
            ...hit,
            span: {
              start: label.span.start + hit.span.start,
              end: label.span.start + hit.span.end,
            },
            fieldPath: label.fieldName,
          });
        }
        continue;
      }
      if (verdict.type === "detect" && verdict.kind === "ip") continue;
    }

    const resolved = resolveLeafFinding(label.value, "string", verdict, options);
    if (!resolved) continue;

    const kind = upgradeAccountToPersonName(
      resolved.kind,
      resolved.surface ?? label.value,
    );

    let value = resolved.surface ?? label.value;
    let span = label.span;
    if (resolved.surface && resolved.surface !== label.value) {
      const offset = label.value.lastIndexOf(resolved.surface);
      if (offset >= 0) {
        span = {
          start: label.span.start + offset,
          end: label.span.start + offset + resolved.surface.length,
        };
        value = resolved.surface;
      }
    }

    findings.push({
      kind,
      value,
      key:
        kind === "person_name"
          ? normalizePersonNameKey(value)
          : kind === resolved.kind
            ? resolved.key
            : value.toLowerCase(),
      span,
      fieldPath: label.fieldName,
      decision: resolved.decision,
    });
  }

  return findings;
}

/** Multi-word `User: Alice Martin` / `user Jean Dupont (` → person, not account. */
function upgradeAccountToPersonName(kind: FindingKind, value: string): FindingKind {
  if (kind !== "account") return kind;
  if (value.includes("@") || value.includes("\\")) return kind;
  if (!value.includes(" ")) return kind;
  // Never promote sentences / ARNs / error messages to person names.
  if (!looksLikePersonNamePhrase(value)) return kind;
  return "person_name";
}

function findingsFromJson(
  source: string,
  documents: Array<{ value: unknown; from: number }>,
  options: RedactOptions,
): Finding[] {
  const findings: Finding[] = [];

  for (const document of documents) {
    const groupEvent = isWindowsGroupEventDoc(document.value);
    const leaves = collectJsonLeaves(source, document.value, document.from);
    for (const leaf of leaves) {
      const path =
        leaf.pathSegments.length > 0
          ? leaf.pathSegments
          : leaf.fieldName
            ? [leaf.fieldName]
            : [];
      const fieldPath = path.join(".");
      const verdict = classifyField(path);
      if (verdict?.type === "protected") continue;
      // Group management events: targetUserName is a group, not an account.
      if (
        groupEvent &&
        verdict?.type === "detect" &&
        verdict.kind === "account" &&
        path[path.length - 1]?.toLowerCase() === "targetusername"
      ) {
        continue;
      }

      const encodedInterior = source.slice(leaf.span.start, leaf.span.end);

      // IP fields: scan inside the decoded value; map hits back into the encoded literal.
      if (
        leaf.valueKind === "string" &&
        ((verdict?.type === "detect" && verdict.kind === "ip") ||
          (verdict?.type === "ambiguous" && verdict.candidates.includes("ip")))
      ) {
        const embedded = [...findIpv4(leaf.raw), ...findIpv6(leaf.raw)];
        if (embedded.length > 0) {
          for (const hit of embedded) {
            const mapped = mapDecodedSpanToEncoded(encodedInterior, hit.span);
            if (!mapped) continue;
            findings.push({
              ...hit,
              value: encodedInterior.slice(mapped.start, mapped.end),
              span: {
                start: leaf.span.start + mapped.start,
                end: leaf.span.start + mapped.end,
              },
              fieldPath,
            });
          }
          continue;
        }
        if (verdict.type === "detect" && verdict.kind === "ip") {
          continue;
        }
      }

      const resolved = resolveLeafFinding(leaf.raw, leaf.valueKind, verdict, options);
      if (resolved) {
        const decodedSurface = resolved.surface ?? leaf.raw;
        let span = leaf.span;
        let encodedValue = encodedInterior;

        if (resolved.surface && resolved.surface !== leaf.raw) {
          // DOMAIN\user - locate user in decoded, map to encoded.
          const decStart = leaf.raw.lastIndexOf(resolved.surface);
          if (decStart >= 0) {
            const mapped = mapDecodedSpanToEncoded(encodedInterior, {
              start: decStart,
              end: decStart + resolved.surface.length,
            });
            if (mapped) {
              span = {
                start: leaf.span.start + mapped.start,
                end: leaf.span.start + mapped.end,
              };
              encodedValue = encodedInterior.slice(mapped.start, mapped.end);
            }
          }
        } else if (leaf.valueKind === "string" && encodedInterior !== leaf.raw) {
          // Escaped JSON string (\uXXXX, \t, …): replace the encoded form at this span.
          encodedValue = encodedInterior;
          span = leaf.span;
        } else {
          encodedValue = decodedSurface;
          if (resolved.surface && resolved.surface !== leaf.raw) {
            span = spanOfSuffix(leaf.span, leaf.raw, resolved.surface);
            encodedValue = resolved.surface;
          }
        }

        findings.push({
          kind: resolved.kind,
          value: encodedValue,
          key: resolved.key,
          span,
          fieldPath,
          decision: resolved.decision,
        });
      }

      // Detectors on the decoded string (full_log prose, \u0040 emails, …).
      if (leaf.valueKind === "string" && leaf.raw.length >= 2) {
        findings.push(
          ...findingsInsideDecodedJsonString(
            source,
            leaf.span,
            encodedInterior,
            leaf.raw,
            fieldPath,
            options,
          ),
        );
      }
    }
  }

  return findings;
}

/** Detect on decoded JSON strings; map hits back to encoded source spans. */
function findingsInsideDecodedJsonString(
  source: string,
  leafSpan: { start: number; end: number },
  encodedInterior: string,
  decoded: string,
  fieldPath: string,
  options: RedactOptions,
): Finding[] {
  const inner = mergeNonOverlapping([
    ...findingsFromTextLabels(decoded, options),
    ...collectLooseFindings(decoded),
  ]);
  const out: Finding[] = [];

  for (const hit of inner) {
    const mapped = mapDecodedSpanToEncoded(encodedInterior, hit.span);
    if (!mapped) continue;
    const encodedValue = encodedInterior.slice(mapped.start, mapped.end);
    out.push({
      ...hit,
      value: encodedValue,
      span: {
        start: leafSpan.start + mapped.start,
        end: leafSpan.start + mapped.end,
      },
      fieldPath,
    });
  }

  void source;
  return out;
}

type ResolvedLeaf = {
  kind: FindingKind;
  key: string;
  decision: "replace" | "keep";
  /** When set, replace this token instead of the whole field raw value. */
  surface?: string;
};

function resolveLeafFinding(
  raw: string,
  valueKind: "string" | "number",
  verdict: FieldVerdict | null,
  options: RedactOptions,
): ResolvedLeaf | null {
  if (valueKind === "string" && isValidEmail(raw)) {
    return { kind: "email", key: raw.toLowerCase(), decision: "replace" };
  }

  if (valueKind === "string" && isValidMac(raw)) {
    return { kind: "mac", key: raw.toLowerCase(), decision: "replace" };
  }

  if (valueKind === "string" && isValidIpv4(raw)) {
    const decision = findIpv4(raw)[0]?.decision ?? "replace";
    return { kind: "ipv4", key: raw, decision };
  }

  if (verdict === null) return null;

  if (verdict.type === "ambiguous") {
    return resolveAmbiguous(raw, valueKind, verdict.candidates, verdict.fallback, options);
  }

  if (verdict.type === "detect") {
    return resolveDetectedKind(raw, valueKind, verdict.kind, options);
  }

  return null;
}

/** Narrow a leaf span to a suffix token (e.g. user in DOMAIN\\user). */
function spanOfSuffix(
  leafSpan: { start: number; end: number },
  raw: string,
  surface: string,
): { start: number; end: number } {
  const offset = raw.lastIndexOf(surface);
  if (offset < 0) return leafSpan;
  return {
    start: leafSpan.start + offset,
    end: leafSpan.start + offset + surface.length,
  };
}

function resolveAmbiguous(
  raw: string,
  valueKind: "string" | "number",
  candidates: readonly FieldKind[],
  fallback: FieldKind,
  options: RedactOptions,
): ResolvedLeaf | null {
  for (const candidate of candidates) {
    if (candidate === "ip") {
      if (valueKind === "string" && isValidIpv4(raw)) {
        const decision = findIpv4(raw)[0]?.decision ?? "replace";
        return { kind: "ipv4", key: raw, decision };
      }
      if (valueKind === "string") {
        const v6 = normalizeIpv6(raw);
        if (v6) {
          const decision = findIpv6(raw)[0]?.decision ?? "replace";
          return { kind: "ipv6", key: v6, decision };
        }
      }
      continue;
    }
    if (candidate === "mac") {
      if (valueKind === "string" && isValidMac(raw)) {
        return { kind: "mac", key: raw.toLowerCase(), decision: "replace" };
      }
      continue;
    }
    if (candidate === "address" || candidate === "hostname") {
      const hit = resolveDetectedKind(raw, valueKind, candidate, options);
      if (hit) return hit;
    }
  }
  return resolveDetectedKind(raw, valueKind, fallback, options);
}

function resolveDetectedKind(
  raw: string,
  valueKind: "string" | "number",
  kind: FieldKind,
  options: RedactOptions,
): ResolvedLeaf | null {
  switch (kind) {
    case "ip":
      return null;
    case "mac":
      if (valueKind !== "string" || !isValidMac(raw)) return null;
      return { kind: "mac", key: raw.toLowerCase(), decision: "replace" };
    case "email":
      if (valueKind !== "string" || !isValidEmail(raw)) return null;
      return { kind: "email", key: raw.toLowerCase(), decision: "replace" };
    case "phone":
      if (valueKind !== "string" || !isPhoneValue(raw)) return null;
      return { kind: "phone", key: normalizePhoneKey(raw), decision: "replace" };
    case "address": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw || trimmed.length < 3) return null;
      return { kind: "address", key: raw.toLowerCase(), decision: "replace" };
    }
    case "geo":
      if (!(valueKind === "number" || isNumericToken(raw))) return null;
      return { kind: "geo", key: raw, decision: "replace" };
    case "hostname": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw || trimmed.length < MIN_IDENTITY_LENGTH) return null;
      if (isSentinelValue(trimmed)) return null;
      // PHP/ truncation artefacts: `db-p...`
      if (trimmed.includes("...")) return null;
      if (isHostnameStopword(trimmed)) return null;
      return {
        kind: "hostname",
        key: normalizeHostnameKey(trimmed),
        decision: isKeptHostname(trimmed) ? "keep" : "replace",
      };
    }
    case "person_name": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw || trimmed.length < MIN_IDENTITY_LENGTH) return null;
      if (isSentinelValue(trimmed)) return null;
      // LDAP group CNs (`Comptabilite-RW`) are not person names.
      if (isGroupLikeCn(trimmed)) return null;
      // TLS / CA short CNs: `R3`, `R10` - public intermediates, not people.
      if (isPublicCaCn(trimmed)) return null;
      // Wildcard / DNS CN (`*.acmecorp.fr`, `login.live.com`).
      if (trimmed.includes("*") || looksLikeDnsName(trimmed)) return null;
      // Long TLS issuer display names mistaken for people.
      if (
        /DigiCert|GlobalSign|Microsoft Azure|Let's Encrypt|ISRG|GeoTrust|Sectigo/i.test(
          trimmed,
        ) ||
        (/\b(?:TLS|SSL|RSA|SHA\d*|Issuing CA)\b/i.test(trimmed) &&
          !looksLikePersonNamePhrase(trimmed))
      ) {
        return null;
      }
      // Generic admin display names stay readable (same policy as accounts).
      if (isKeptAccount(trimmed)) return null;
      if (isPersonNameStopword(trimmed)) return null;
      // Reject sentence-length "names" (CloudTrail error messages, etc.).
      if (trimmed.includes(" ") && !looksLikePersonNamePhrase(trimmed)) return null;
      return {
        kind: "person_name",
        key: normalizePersonNameKey(trimmed),
        decision: "replace",
      };
    }
    case "account": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw) return null;
      // Postfix `user=<a@b>` / `to=<a@b>` - angle-bracketed mailbox, not a login.
      if (trimmed.startsWith("<") && trimmed.endsWith(">")) {
        const inner = trimmed.slice(1, -1);
        if (isValidEmail(inner)) {
          return {
            kind: "email",
            key: inner.toLowerCase(),
            decision: "replace",
            surface: inner,
          };
        }
      }
      if (isValidEmail(trimmed)) {
        return {
          kind: "email",
          key: trimmed.toLowerCase(),
          decision: "replace",
        };
      }
      // DOMAIN\user → account is the user part only (never the AD domain).
      const slash = trimmed.lastIndexOf("\\");
      let account = slash >= 0 ? trimmed.slice(slash + 1) : trimmed;
      // One token only - never swallow a following password argv OR an error
      // sentence after `User: arn:… is not authorized…`.
      // Keep multi-word person display names: `user=Mehdi El Amrani`.
      if (!looksLikePersonNamePhrase(account)) {
        const tokenEnd = account.search(/[\s;]/);
        if (tokenEnd >= 0) account = account.slice(0, tokenEnd);
      }
      // AWS ARN / path: only the login after `user/`.
      const arnUser = /(?:^|\/)user\/([^/\s]+)$/i.exec(account);
      if (arnUser) account = arnUser[1]!;
      // UPN `user@realm` classified as account → share key with bare login / email.
      const at = account.indexOf("@");
      if (at > 0 && isValidEmail(account)) {
        return {
          kind: "email",
          key: account.toLowerCase(),
          decision: "replace",
          surface: account,
        };
      }
      if (at > 0) {
        account = account.slice(0, at);
      }
      if (isAccountStopword(account)) return null;
      if (/^u[0-9a-fA-F]{4}/.test(account)) return null;
      if (account.startsWith("arn:")) return null;

      // Machine SAM `HOST$` → hostname (same alias as agent.name / computer FQDN).
      if (isMachineAccount(account)) {
        return {
          kind: "hostname",
          key: normalizeHostnameKey(account),
          decision: "replace",
          surface: account,
        };
      }

      const needsSurface = account !== trimmed;
      if (!isRedactableAccount(account)) {
        if (isSentinelValue(account) || account.length < MIN_IDENTITY_LENGTH) return null;
        return {
          kind: "account",
          key: account.toLowerCase(),
          decision: "keep",
          ...(needsSurface || slash >= 0 ? { surface: account } : {}),
        };
      }
      return {
        kind: "account",
        key: account.toLowerCase(),
        decision: "replace",
        ...(needsSurface || slash >= 0 ? { surface: account } : {}),
      };
    }
    case "internal_id": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw) return null;
      return {
        kind: "internal_id",
        key: raw,
        decision: options.redactInternalIds ? "replace" : "keep",
      };
    }
    case "business_id": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw) return null;
      return {
        kind: "business_id",
        key: raw,
        decision: options.redactBusinessIds ? "replace" : "keep",
      };
    }
    case "birth_date": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || trimmed !== raw) return null;
      return { kind: "birth_date", key: raw, decision: "replace" };
    }
    case "secret": {
      if (valueKind !== "string") return null;
      const trimmed = raw.trim();
      if (!trimmed || isSentinelValue(trimmed)) return null;
      if (trimmed.length < 4) return null;
      // PWD=/home/… is a working directory, not a password.
      if (looksLikeFilesystemPath(trimmed)) return null;
      // Bare dates may be passwords (`password=1987-05-03`) - keep as secret.
      // Propagation is blocked in `isPropagatableSecret` so timestamps survive.
      // Placeholders / PAM types: `(using password: YES)`, `passwd:chauthtok`.
      // Glued secrets may contain `=` (`Summer=2026!`, base64 `…==`) - do not
      // reject those here; empty-field borrows are filtered at parse time.
      if (/^(YES|NO|TRUE|FALSE|ON|OFF|OK)$/i.test(trimmed)) return null;
      if (/^(chauthtok|auth|account|session)$/i.test(trimmed)) return null;
      // Cisco `Invalid password : server =` - next field label, not a secret.
      if (
        /^(server|host|hostname|user|username|login|reason|status|attempts|policy|link|type|name|label|from)$/i.test(
          trimmed,
        )
      ) {
        return null;
      }
      // Auth scheme words alone are not secrets.
      if (AUTH_SCHEMES.has(trimmed.toLowerCase())) return null;
      // `Bearer <token>` / `Basic <b64>` - replace only the credential token.
      const scheme = /^(bearer|basic|digest|negotiate|ntlm)\s+/i.exec(trimmed);
      if (scheme) {
        let token = trimmed.slice(scheme[0].length).trim();
        // Never swallow a closing quote / delimiter into the secret.
        token = token.replace(/["'\s]+$/g, "");
        if (!token || isSentinelValue(token) || AUTH_SCHEMES.has(token.toLowerCase())) {
          return null;
        }
        return {
          kind: "secret",
          key: token,
          decision: "replace",
          surface: token,
        };
      }
      return { kind: "secret", key: raw, decision: "replace" };
    }
    default: {
      const _exhaustive: never = kind;
      void _exhaustive;
      return null;
    }
  }
}

function isNumericToken(value: string): boolean {
  if (!value) return false;
  return Number.isFinite(Number(value));
}

/** Let's Encrypt / public CA intermediate CNs. */
function isPublicCaCn(value: string): boolean {
  const v = value.trim();
  if (/^R\d{1,3}$/i.test(v)) return true;
  if (/^ISRG Root/i.test(v)) return true;
  if (v.length <= 3 && !/\s/.test(v) && /^[A-Z0-9]+$/i.test(v)) return true;
  return false;
}

function looksLikeDnsName(value: string): boolean {
  if (!value.includes(".")) return false;
  if (/\s/.test(value)) return false;
  // Require a real TLD (≥2 chars) so nicknames like `lea.m` stay person names.
  if (!/\.[A-Za-z]{2,}$/.test(value)) return false;
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(
    value,
  );
}

function normalizePhoneKey(value: string): string {
  let digits = "";
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 48 && code <= 57) digits += value[i]!;
  }
  return digits;
}

function buildMappings(findings: Finding[], options: RedactOptions): MappingEntry[] {
  const factory = createAliasFactory(options.alias);
  // Reserve every original IP so the pool never emits an alias equal to
  // another address present in this document (silent corruption under the
  // old sequential applicator; still desirable for stable, injective aliases).
  for (const finding of findings) {
    if (
      finding.decision === "replace" &&
      (finding.kind === "ipv4" || finding.kind === "ipv6")
    ) {
      factory.reserveIp(finding.value);
      if (finding.key !== finding.value) factory.reserveIp(finding.key);
    }
  }
  const byKey = new Map<string, MappingEntry>();

  for (const finding of findings) {
    const mapKey = `${finding.kind}:${finding.key}`;
    const existing = byKey.get(mapKey);
    if (existing) {
      existing.occurrenceCount += 1;
      if (finding.decision === "keep") existing.decision = "keep";
      if (finding.value !== existing.original) {
        const variants = existing.variants ?? [];
        if (!variants.includes(finding.value)) {
          variants.push(finding.value);
          existing.variants = variants;
        }
      }
      if (
        finding.kind === "secret" ||
        needsSpanOnlyReplace(finding.value, finding.kind)
      ) {
        existing.spans = [...(existing.spans ?? []), finding.span];
      }
      continue;
    }

    const alias = factory.aliasFor(finding.kind, finding.key, finding.value);
    const entry: MappingEntry = {
      kind: finding.kind,
      original: finding.value,
      alias,
      decision: finding.decision,
      occurrenceCount: 1,
    };
    // Secrets always keep their detection spans (`-pHiver#2026` has a letter
    // glued before the value - the trie boundary would refuse it).
    if (
      finding.kind === "secret" ||
      needsSpanOnlyReplace(finding.value, finding.kind)
    ) {
      entry.spans = [finding.span];
    }
    byKey.set(mapKey, entry);
  }

  // Known full names → also redact first/last tokens alone with the same alias
  // (`Léa Moreau` ⇒ `Léa`, `Bonjour Nadia`, subject `Marchand`, …).
  for (const entry of byKey.values()) {
    if (entry.kind !== "person_name" || entry.decision !== "replace") continue;
    const surface = decodePersonSurface(entry.original);
    const parts = surface
      .split(/[\s_]+/)
      .map((p) => p.replace(/^[,."]+|[,."]+$/g, ""))
      .filter((p) => p.length >= MIN_IDENTITY_LENGTH && !/=[0-9A-Fa-f]{2}/.test(p));
    if (parts.length < 2) continue;
    const variants = entry.variants ?? [];
    const add = (part: string, role: "first" | "last") => {
      if (isPersonNameStopword(part)) return;
      if (/^\d+$/.test(part)) return;
      if (part === entry.original) return;
      // First-name-only propagation is dangerous for common nouns (`Rose`,
      // `Grace`) that appear in ordinary French/English prose.
      if (role === "first" && isAmbiguousGivenName(part)) return;
      if (!variants.includes(part)) variants.push(part);
      const upper = part.toUpperCase();
      if (upper !== part && !variants.includes(upper)) variants.push(upper);
    };
    add(parts[0]!, "first");
    add(parts[parts.length - 1]!, "last");
    // Decoded full form (`Léa Moreau`) when original was MIME Q-encoded.
    if (surface !== entry.original && !variants.includes(surface)) {
      variants.push(surface);
    }
    if (variants.length > 0) entry.variants = variants;
  }

  return [...byKey.values()];
}

/** True when this finding must stay span-only (weak secrets, short numbers, …). */
function needsSpanOnlyReplace(value: string, kind?: FindingKind): boolean {
  if (kind === "secret") return !isPropagatableSecret(value);
  // JSON escapes / Windows paths - never globally propagate encoded forms.
  if (value.includes("\\")) return true;
  // URL-encoded query names (`Siobh%C3%A1n+O%27Brien`) - span only.
  if (kind === "person_name" && (value.includes("%") || value.includes("+"))) {
    return true;
  }
  if (value.length >= 6) return false;
  return /^\d+$/.test(value);
}

/** True when a secret is strong enough to propagate globally. */
function isPropagatableSecret(value: string): boolean {
  if (value.length < 8) return false;
  if (/^\d+$/.test(value)) return false;
  if (/^[a-z]+$/.test(value) && value.length < 16) return false;
  if (WEAK_SECRET_WORDS.has(value.toLowerCase())) return false;
  // Bare dates/times may be passwords (`password=1987-05-03`) and do propagate,
  // but applyFast skips syslog timestamp contexts (see `isLogTimestampContext`).
  return true;
}

/** Classic brute-force / test passwords that also appear as log vocabulary. */
const WEAK_SECRET_WORDS = new Set([
  "password",
  "passwords",
  "localhost",
  "changeme",
  "administrator",
  "adminadmin",
  "qwertyuiop",
  "letmein12",
  "welcome1",
  "welcome12",
  "password1",
  "password12",
  "passw0rd",
  "p@ssw0rd",
  "secret12",
  "default1",
  "testtest",
  "useruser",
  "guestguest",
]);

function looksLikeFilesystemPath(value: string): boolean {
  if (value.startsWith("/") || value.startsWith("~")) return true;
  if (/^[A-Za-z]:[\\/]/.test(value)) return true;
  if (value.startsWith("\\\\")) return true;
  return false;
}

/** Given names that are also common words - do not propagate alone. */
function isAmbiguousGivenName(part: string): boolean {
  return /^(rose|grace|hope|joy|may|june|april|august|elle|marc|jean|paul|pierre|marie|ange|aime|aimee|aimeé|clair|claire|vincent|constant|aime)$/i.test(
    part,
  );
}

/** MIME Q (`L=C3=A9a_Moreau`) or plain (`Léa Moreau`) → display surface. */
function decodePersonSurface(value: string): string {
  if (!/=[0-9A-Fa-f]{2}/.test(value) && !value.includes("_")) return value;
  const spaced = value.replace(/_/g, " ");
  try {
    return decodeURIComponent(spaced.replace(/=([0-9A-Fa-f]{2})/g, "%$1"));
  } catch {
    return spaced;
  }
}

/** Adapt canonical alias to surface form (::ffff:, HOST$, %40 emails). */
function surfaceAlias(alias: string, original: string): string {
  if (/^::ffff:/i.test(original) && !/^::ffff:/i.test(alias)) {
    return `::ffff:${alias}`;
  }
  if (original.endsWith("$") && !alias.endsWith("$") && !alias.includes("@")) {
    return `${alias}$`;
  }
  if (/%40/i.test(original) && alias.includes("@")) {
    return alias.replace("@", "%40");
  }
  return alias;
}

function mergeNonOverlapping(findings: Finding[]): Finding[] {
  const sorted = findings
    .slice()
    .sort((a, b) => a.span.start - b.span.start || b.span.end - a.span.end);
  const merged: Finding[] = [];
  let lastEnd = -1;

  for (const finding of sorted) {
    if (finding.span.start < lastEnd) continue;
    merged.push(finding);
    lastEnd = finding.span.end;
  }

  return merged;
}

const AUTH_SCHEMES = new Set(["bearer", "basic", "digest", "negotiate", "ntlm"]);

/** Windows Security event IDs that operate on groups (targetUserName = group). */
function isWindowsGroupEventDoc(value: unknown): boolean {
  const id = findWinEventId(value);
  if (id === null) return false;
  if (id >= 4727 && id <= 4735) return true;
  if (id === 4737) return true;
  if (id >= 4744 && id <= 4758) return true;
  return false;
}

function findWinEventId(value: unknown): number | null {
  if (!value || typeof value !== "object") return null;
  const root = value as Record<string, unknown>;
  const win = root.data && typeof root.data === "object"
    ? (root.data as Record<string, unknown>).win
    : root.win;
  if (!win || typeof win !== "object") return null;
  const system = (win as Record<string, unknown>).system;
  if (!system || typeof system !== "object") return null;
  const raw = (system as Record<string, unknown>).eventID;
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw)) return Number(raw);
  return null;
}
