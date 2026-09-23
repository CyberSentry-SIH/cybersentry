# Origin Traceability & Attribution Confidence Framework (F07)

## Overview
CyberSentry computes email origin traceability by evaluating the boundary hop connecting IP, reverse DNS (FCrDNS), cryptographic authentication (SPF/DKIM/DMARC), geolocation, and threat intelligence.

## Attribution Verdicts

| Verdict | Description | Forensic Criteria |
|---|---|---|
| `SPOOFED_DOMAIN` | Forged sender domain | Boundary IP not authorized by SPF; DKIM signature absent or invalid. |
| `COMPROMISED_ACCOUNT` | Authentic domain sending threats | SPF and DKIM PASS on legitimate domain, but body contains malicious URLs, malware, or extortion. |
| `ANONYMIZED_INFRA` | Anonymizing relay / Tor | Connecting IP matches known Tor exit node or bulletproof proxy network. |
| `DIRECT_MALICIOUS_INFRA` | Attacker-controlled lookalike infrastructure | Domain is a lookalike/typosquat registered specifically for the attack. |
| `LEGITIMATE_INFRA` | Authentic email from verified sender | All SPF/DKIM/DMARC checks PASS with no malicious payloads or deceptive links. |
| `INDETERMINATE` | Inconclusive telemetry | Missing intermediate Received headers or unresolvable internal IP hops. |

## Legal Disclaimer
Origin assessments represent technical forensic corroboration. Definitive attribution of individual human actors requires lawful ISP logs and subscriber identification records.
