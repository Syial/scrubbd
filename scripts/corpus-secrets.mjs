/**
 * Corpus files never store provider-format fake secrets in clear: the recognisable
 * prefix is replaced by a `{{name}}` marker so that secret scanners (GitHub push
 * protection, gitleaks, ...) do not flag the repository. Every reader of corpus files
 * (redact-corpus.ts, check-corpus.mjs) calls `expandSecrets()` first, so the redactor and the
 * checker always see the real strings.
 *
 * Add a new marker here only; `{{` must not otherwise occur in corpus files.
 */
export const SECRET_PREFIXES = {
  ghp: "ghp_",
  gho: "gho_",
  ghu: "ghu_",
  ghs: "ghs_",
  ghr: "ghr_",
  github_pat: "github_pat_",
  AKIA: "AKIA",
  ASIA: "ASIA",
  ABIA: "ABIA",
  ACCA: "ACCA",
  AGPA: "AGPA",
  AIDA: "AIDA",
  AIPA: "AIPA",
  ANPA: "ANPA",
  ANVA: "ANVA",
  AROA: "AROA",
  APKA: "APKA",
  sk_live: "sk_live_",
  sk_test: "sk_test_",
  rk_live: "rk_live_",
  rk_test: "rk_test_",
  pk_live: "pk_live_",
  pk_test: "pk_test_",
  xoxa: "xoxa-",
  xoxb: "xoxb-",
  xoxp: "xoxp-",
  xoxr: "xoxr-",
  xoxs: "xoxs-",
  glpat: "glpat-",
  AIza: "AIza",
  SG: "SG.",
  PRIVATE_KEY: "PRIVATE KEY",
};

const MARKER = /\{\{([A-Za-z_]+)\}\}/g;

/** Replace every `{{name}}` marker by its real prefix; unknown markers are left untouched. */
export function expandSecrets(text) {
  return text.replace(MARKER, (whole, name) => SECRET_PREFIXES[name] ?? whole);
}
