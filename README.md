# Labs, Code, & Reports

Security research and assessment reports shared publicly.

## Reports

### Web Application Penetration Test - Network Management System (NMS)

**[Read the full report](https://1mgr00t90.github.io/reports/nms-pentest-report/)**

A manual, authorized web application penetration test of the firewall management module of an internally
developed Network Management System. The assessment identified one High and three Medium severity findings,
principally a stored cross-site scripting vulnerability in the firewall rule comment field.

| | |
|---|---|
| **Reference** | PT-NMS-2025-001 |
| **Type** | Manual grey-box web application penetration test |
| **Findings** | 1 High, 3 Medium, 1 Low, 1 Informational |
| **Key finding** | Stored XSS - CVSS v3.1 8.7 (High), CWE-79 |
| **Standards** | OWASP WSTG v4.2, OWASP Top 10:2021, CWE, CAPEC, CVSS v3.1 |

Testing was conducted with written authorization from the system owner against a non-production development
instance. All identifying detail has been redacted for publication.

### Web Application Security Assessment - Cryptocurrency Threat-Intelligence Platform

**[Read the full report](https://1mgr00t90.github.io/reports/cryptosite-vuln-assesment/)**

A manual, authorized black-box security assessment of a public-facing cryptocurrency threat-intelligence platform
and its API. The assessment identified two High and one Medium severity findings, spanning broken access control,
broken rate limiting, and origin-server exposure behind a CDN.

| | |
|---|---|
| **Reference** | VA-CTIP-2026-002 |
| **Type** | Manual black-box web application and API security assessment |
| **Findings** | 2 High, 1 Medium |
| **Key findings** | Unauthenticated access to paid-tier API data; password-reset email flooding despite rate limit; Cloudflare origin bypass |
| **Standards** | OWASP WSTG v4.2, OWASP Top 10:2021, OWASP API Top 10:2023, CWE, CVSS v3.1 |

Testing was conducted with written authorization from the platform owner. The organization identity, domain, origin
IP and all other identifying detail have been redacted for publication.
