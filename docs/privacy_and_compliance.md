# Privacy, Encryption, and DPDP Act Compliance (F13)

## Overview
CyberSentry incorporates privacy-by-design principles aligning with India's Digital Personal Data Protection (DPDP) Act, 2023:
1. **Evidence Encryption at Rest**: All stored `.eml` evidence files are symmetrically encrypted on disk using AES-256 (Fernet) keys.
2. **Context-Aware PII Masking**: In-flight redaction of Indian mobile numbers, Aadhaar numbers, PAN cards, UPI identifiers, and IFSC codes before passing telemetry to external intelligence providers.
3. **Chain of Custody & Immutability**: Cryptographic SHA-256 provenance logging for all forensic inspections.
4. **Retention Policies**: Configurable data retention with mandatory Legal Hold and Active Case protection against unlawful destruction.
