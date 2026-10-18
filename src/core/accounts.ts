import { isSentinelValue, MIN_IDENTITY_LENGTH } from "./sentinels";

/** Well-known / generic / classic-attack accounts that must stay readable. */
const KEEP_ACCOUNTS = new Set(
  [
    "root",
    "admin",
    "administrator",
    "administrateur",
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "nt authority",
    "backup",
    "nobody",
    "daemon",
    "www-data",
    "nginx",
    "apache",
    "postgres",
    "mysql",
    "oracle",
    "ubuntu",
    "ec2-user",
    "guest",
    "user",
    "account",
    "login",
    "logon",
    "test",
    "git",
    "ftp",
    "anonymous",
    "pi",
    "centos",
    "debian",
    "enable_15",
    "hidden_due_to_security_reasons",
    "system:anonymous",
    "unix-session",
  ].map((s) => s.toLowerCase()),
);

export function isKeptAccount(value: string): boolean {
  return KEEP_ACCOUNTS.has(value.trim().toLowerCase());
}

/** True when a token is eligible to be redacted as an account. */
export function isRedactableAccount(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < MIN_IDENTITY_LENGTH) return false;
  if (isSentinelValue(trimmed)) return false;
  if (isKeptAccount(trimmed)) return false;
  if (/^\d+$/.test(trimmed)) return false;
  // Slack / Discord snowflake-style ids: U024BE7LH, C0123ABCD (uppercase + digit).
  // Case-sensitive: lowercase `crousseau` must stay redactable.
  if (/^[UWC][A-Z0-9]*\d[A-Z0-9]*$/.test(trimmed) && trimmed.length >= 9) {
    return false;
  }
  // Kubernetes subjects: system:serviceaccount:…
  if (/^system:/i.test(trimmed)) return false;
  return true;
}
