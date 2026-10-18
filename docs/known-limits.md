# Known limits / open design decisions

Cases marked `D` in the corpora: no single correct redaction. Kept here so they are not lost when line-by-line reading keys were removed.

| Corpus | File | Line | Value | Note |
|---|---|---:|---|---|
| corpus | `01-nginx-access.log` | 4 | `uid=48213` | internal user id: alias or not? |
| corpus | `01-nginx-access.log` | 10 | `Élodie-Fontaine` | name in a URL path: no structural hint |
| corpus | `01-nginx-access.log` | 11 | `dupont+jean` | name in a search query |
| corpus | `01-nginx-access.log` | 13 | `app.3.2.1.4.js` | filename with 4 numbers: valid IPv4, but in context it is a filename |
| corpus | `02-auth-syslog.log` | 1 | `oracle` | made-up account tried by an attacker: useful to the analyst, not personal data |
| corpus | `02-auth-syslog.log` | 4 | `SHA256:q3XvK0lYk1m5P7nJbGf0eE3a1Jx4yq0Z8s0t5uH2vRk` | SSH key fingerprint: correlation id, keep by default? |
| corpus | `02-auth-syslog.log` | 7 | `2001:db8:85a3::8a2e:370:7334` | documentation IPv6 (RFC 3849): keep if following the special-ranges rule |
| corpus | `03-wazuh-windows.ndjson` | 1 | `"targetDomainName":"FAKECORP"` | NetBIOS domain name: keep or alias? |
| corpus | `03-wazuh-windows.ndjson` | 2 | `"targetUserSid":"S-1-5-21-3623811015-3361044348-30300820-1013"` | domain SID: identifies the domain (domain SID) and the user (RID 1013) |
| corpus | `03-wazuh-windows.ndjson` | 2 | `"subjectUserName":"PC-COMPTA-07$"` | machine account (hostname + $): treated as host or as account? |
| corpus | `03-wazuh-windows.ndjson` | 5 | `"subjectUserName":"Administrateur"` | generic French account: missing from the admin/root list? |
| corpus | `03-wazuh-windows.ndjson` | 6 | `"destinationHostname":"par21s22-in-f14.1e100.net"` | PUBLIC hostname (Google reverse DNS): keep? useful info for the analyst |
| corpus | `03-wazuh-windows.ndjson` | 8 | `DC=fakecorp,DC=org` | domain in a DN |
| corpus | `03-wazuh-windows.ndjson` | 10 | `9007199254740993` | integer > 2^53: never round it (JSON.parse + stringify corrupts it) |
| corpus | `04-app-pii.log` | 10 | `app_crm` | application service account: keep (useful) or alias? |
| corpus | `04-app-pii.log` | 14 | `Mme Martin` | title + last name alone: very ambiguous ("Martin" is also a first name and a common company name) |
| corpus | `04-app-pii.log` | 15 | `jean [dot] dupont [at] example [dot] com` | obfuscated email: known limit, to document |
| corpus | `04-app-pii.log` | 16 | `48.8698, 2.3312` | unlabeled number pair: could be anything |
| corpus | `04-app-pii.log` | 17 | `user_id=48213` | user id |
| corpus | `04-app-pii.log` | 18 | `17.0.9.1` | version that is also a valid IPv4: must stay intact |
| corpus | `04-app-pii.log` | 22 | `Martin & Fils SARL` | company name containing a last name: do not confuse with a person |
| corpus | `05-firewall-kv.log` | 1 | `devid="FGT60FTK20000001"` | firewall serial number |
| corpus | `05-firewall-kv.log` | 2 | `hostname="www.exemple.fr"` | visited public website: keep (the analyst needs it) |
| corpus | `05-firewall-kv.log` | 6 | `fe80::ba27:ebff:fe12:3456` | EUI-64 link-local: derived from the machine MAC, so replacing is defensible; keeping also (non-routable address) |
| corpus | `06-edge-cases.log` | 2 | `100.64.0.1` | CGNAT (RFC 6598): neither public nor private in the RFC 1918 sense |
| corpus | `06-edge-cases.log` | 4 | `192.0.2.10` | RFC 5737 documentation range: keep (special-ranges rule) |
| corpus | `06-edge-cases.log` | 4 | `198.51.100.7` | same |
| corpus | `06-edge-cases.log` | 4 | `203.0.113.9` | same |
| corpus | `06-edge-cases.log` | 5 | `1.2.3.4.5` | 5 numbers: neither an IP nor an "IP subset" to split |
| corpus | `06-edge-cases.log` | 6 | `01.02.03.04` | leading zeros: ambiguous (octal?), strict parsers reject |
| corpus | `06-edge-cases.log` | 6 | `08.08.08.08` | same |
| corpus | `06-edge-cases.log` | 8 | `zip=75002` | postal code with "zip" label |
| corpus | `06-edge-cases.log` | 9 | `fe80::1ff:fe23:4567:890a%eth0` | EUI-64 link-local: derived from the machine MAC, so replacing is defensible; keeping also (non-routable address) |
| corpus | `06-edge-cases.log` | 9 | `2001:db8::1` | RFC 3849 documentation |
| corpus | `06-edge-cases.log` | 11 | `kernel=5.15.0.89` | valid IPv4 but preceded by "kernel=": context |
| corpus | `06-edge-cases.log` | 13 | `luhnok=4111111111111111` | 16 Luhn-valid digits BUT label "luhnok": without context, ambiguous |
| corpus | `06-edge-cases.log` | 15 | `ref=01 23 45 67 89` | looks like a FR landline but labeled "ref" |
| corpus | `06-edge-cases.log` | 18 | `S-1-5-21-3623811015-3361044348-30300820-1013` | Windows SID |
| corpus | `06-edge-cases.log` | 21 | `user@localhost` | without TLD |
| corpus | `06-edge-cases.log` | 21 | `foo@bar` | without TLD |
| corpus | `06-edge-cases.log` | 21 | `a@b.c` | one-letter TLD: invalid |
| corpus | `06-edge-cases.log` | 22 | `git@github.com:fakecorp/crm.git` | SSH git: looks like an email, but "git" is a generic account |
| corpus | `06-edge-cases.log` | 23 | `jean.dupont&#64;example.com` | @ as an HTML entity: evasion |
| corpus | `06-edge-cases.log` | 23 | `exa​mple.com` | zero-width character in the domain: evasion |
| corpus | `06-edge-cases.log` | 25 | `anonymous:guest@` | anonymous FTP: not a real secret |
| corpus | `06-edge-cases.log` | 29 | `host=ubuntu-server` | default Ubuntu hostname |
| corpus | `06-edge-cases.log` | 29 | `from=mail.google.com` | public domain name |
| corpus | `06-edge-cases.log` | 30 | `zip=75011` | postal code with label |
| corpus2 | `10-apache-access.log` | 1 | `www.fakecorp.org:443` | vhost = organization domain: keep or alias (policy) |
| corpus2 | `11-apache-error-php.log` | 3 | `'app_crm'` | application service account: keep (it explains the error) or alias |
| corpus2 | `11-apache-error-php.log` | 9 | `smtp.fakecorp.org` | organization public host |
| corpus2 | `12-iis-w3c.log` | 6 | `https://mail.fakecorp.org/owa/auth/logon.aspx` | referer on the organization domain |
| corpus2 | `12-iis-w3c.log` | 10 | `svc_backup` | service account: keep or alias |
| corpus2 | `15-suricata-eve.ndjson` | 6 | `CN=mail.fakecorp.org` | organization domain name in the certificate |
| corpus2 | `19-cloudtrail.ndjson` | 1 | `123456789012` | AWS account id: identifies the organization |
| corpus2 | `19-cloudtrail.ndjson` | 1 | `AIDA…EXAMPLE` | IAM user internal id |
| corpus2 | `19-cloudtrail.ndjson` | 4 | `fakecorp-hr-payroll` | bucket name that contains the organization name |
| corpus2 | `20-azure-signin.json` | 7 | `1d1f0000-0000-0000-0000-00000000000b` | user object id |
| corpus2 | `20-azure-signin.json` | 28 | `"city": "Lyon"` | city |
| corpus2 | `20-azure-signin.json` | 83 | `"state": "Île-de-France"` | region |
| corpus2 | `21-windows-events-xml.log` | 1 | `S-1-5-21-3623811015-3361044348-30300820-1104` | domain SID + user RID: identifies the domain and the person |
| corpus2 | `21-windows-events-xml.log` | 6 | `\\*\paie` | share name: may be sensitive |
| corpus2 | `21-windows-events-xml.log` | 12 | `>svc_backup<` | service account |
| corpus2 | `22-cef-leef.log` | 6 | `domain=FAKECORP` | NetBIOS domain |
| corpus2 | `23-linux-audit-auth.log` | 4 | `6375726C202D75206C65612E6D6F726561753A53756D6D657232303236212068747470733A2F2…` | command line hex-encoded by auditd: contains a password, but invisible without decoding |
| corpus2 | `24-mail-postfix-dovecot.log` | 2 | `helo=<mail.evil-example.test>` | sender HELO name |
| corpus2 | `24-mail-postfix-dovecot.log` | 5 | `4F2A1B2C3D@mail.example.net` | message id that contains a sender hostname |
| corpus2 | `24-mail-postfix-dovecot.log` | 11 | `AGxlYS5tb3JlYXVAZmFrZWNvcnAub3JnAFN1bW1lcjIwMjYh` | SASL PLAIN reply in base64: contains the id and password, invisible without decoding |
| corpus2 | `25-email-message.eml` | 3 | `mx1.fakecorp.org` | organization receiving server |
| corpus2 | `25-email-message.eml` | 10 | `RmFjdHVyZSBuwrAgMjAyNi0wNDUxIOKAlCBNbWUgTWFydGlu` | MIME base64-encoded subject: "Facture n° 2026-0451 - Mme Martin", contains a name |
| corpus2 | `25-email-message.eml` | 11 | `Lemaire & Fils` | company name |
| corpus2 | `25-email-message.eml` | 20 | `Bonjour Léa` | first name alone in the body |
| corpus2 | `25-email-message.eml` | 27 | `Example Net SAS` | company name |
| corpus2 | `26-sql-databases.log` | 3 | `user "app_crm"` | service account |
| corpus2 | `26-sql-databases.log` | 7 | `CREATE ROLE svc_report` | service role name |
| corpus2 | `26-sql-databases.log` | 11 | `'Dupont%'` | literal name in a LIKE |
| corpus2 | `27-docker-k8s.ndjson` | 5 | `"fakecorp-prod"` | namespace name containing the organization name |
| corpus2 | `27-docker-k8s.ndjson` | 7 | `bm90aWZpY2F0aW9uc0BmYWtlY29ycC5vcmc=` | base64-encoded identifier |
| corpus2 | `27-docker-k8s.ndjson` | 9 | `system:node:node-01` | node name |
| corpus2 | `28-dns-servers.log` | 10 | `(8)fakecorp(5)local(0)` | organization domain, length+label format |
| corpus2 | `29-panos-traffic.csv` | 7 | `vpn.fakecorp.org` | organization VPN gateway name |
| corpus2 | `31-shell-history.log` | 17 | `cn=admin,dc=fakecorp,dc=org` | admin DN with the organization domain |
| corpus2 | `32-config-dump.log` | 20 | `notifications@fakecorp.org` | functional notification address |
| corpus2 | `32-config-dump.log` | 24 | `S3cr3t-k8s` | the value is on the line after the name: requires multi-line context |
| corpus2 | `33-crm-export.csv` | 2 | `Lyon` | city |
| corpus2 | `33-crm-export.csv` | 3 | `Lemaire & Fils` | company name |
| corpus2 | `33-crm-export.csv` | 5 | `Né à Hanoï, parle vietnamien` | sensitive information (origin) in free text |
| corpus2 | `33-crm-export.csv` | 7 | `Martin & Fils SARL` | company name containing a last name |
| corpus2 | `34-java-stacktrace.log` | 2 | `'app_crm'` | service account |
| corpus2 | `34-java-stacktrace.log` | 10 | `mail.fakecorp.org` | organization host |
| corpus2 | `34-java-stacktrace.log` | 11 | `started by svc_crm` | service account |
| corpus2 | `35-ldap-directory.ldif` | 1 | `OU=Compta,OU=Utilisateurs,DC=fakecorp,DC=org` | organization directory structure |
| corpus2 | `35-ldap-directory.ldif` | 15 | `l: Lyon` | city ("l" attribute) |
| corpus2 | `35-ldap-directory.ldif` | 20 | `employeeID: 004412` | metric |
| corpus2 | `35-ldap-directory.ldif` | 22 | `AQUAAAAAAAUVAAAAx3pQ1HxUR8NkRpg+zQQAAA==` | SID in base64 (binary LDIF value with "::") |
| corpus2 | `35-ldap-directory.ldif` | 24 | `Compte de Léa` | first name in free text |
| corpus2 | `37-network-syslog-misc.log` | 3 | `server: www.fakecorp.org` | organization server name |
| corpus3 | `41-vendor-messages.log` | 4 | `oracle` | username guessed by an attacker: keep or replace |
| corpus3 | `42-k8s-resources.ndjson` | 5 | `cluster-admin-ines` | first name embedded in a resource name (ClusterRoleBinding) |
| corpus3 | `45-tls-http.ndjson` | 1 | `*.acmecorp.fr` | organization domain in the certificate |
| corpus3 | `46-email-greetings.eml` | 13 | `Gwenaëlle` | isolated first name with no context: likely limit |
| corpus3 | `47-filenames-paths.log` | 5 | `acmecorp-hr-docs` | bucket name containing the organization name |
| corpus3 | `49-user-at-host.log` | 3 | `deploy` | service account |
| corpus3 | `49-user-at-host.log` | 9 | `svc_ftp` | service account |
| corpus3 | `49-user-at-host.log` | 10 | `bastion.acmecorp.fr` | organization public host |
| corpus3 | `57-repeated-secrets.log` | 4 | `azertyuiop` | weak all-lowercase secret: the edge case between "common word" and "real secret" |
| corpus3 | `57-repeated-secrets.log` | 9 | `Welcome1` | "classic" secret quoted in prose |
| corpus3 | `60-empty-field-date.log` | 1 | `2026-10-15` | ambiguous: empty field followed by a date, or password that is a date? Bias toward safety: masking LOCALLY is acceptable; what is not is PROPAGATING it across the whole file (line 6) |
| corpus3 | `60-empty-field-date.log` | 2 | `2026-10-15T10:00:00Z` | ambiguous: empty field followed by a date, or password that is a date? Bias toward safety: masking LOCALLY is acceptable; what is not is PROPAGATING it across the whole file (line 6) |
| corpus3 | `60-empty-field-date.log` | 3 | `11:00:05` | ambiguous: empty field followed by a date, or password that is a date? Bias toward safety: masking LOCALLY is acceptable; what is not is PROPAGATING it across the whole file (line 6) |
| corpus3 | `60-empty-field-date.log` | 4 | `12:30:45` | ambiguous: empty field followed by a date, or password that is a date? Bias toward safety: masking LOCALLY is acceptable; what is not is PROPAGATING it across the whole file (line 6) |
| corpus3 | `61-date-passwords.log` | 6 | `1987-05-03` | with space after ":": ambiguous with an empty field followed by a date |
