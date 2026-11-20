# Labs, Code & Reports

**Offensive security portfolio — web applications, APIs, security assessments, and detection engineering.**

[View the portfolio](https://1mgr00t90.github.io/)

A collection of selected security assessment reports, bug bounty research, and engineering work. The focus is manual testing, reproducible technical evidence, practical remediation, and the security controls that follow an assessment.

## Security Reports

### [Regional API Proxy — SSRF Bug Bounty Report](https://1mgr00t90.github.io/reports/regional-api-ssrf/)

**SSRF · Web/API · Bug bounty**

A redacted report documenting server-side request forgery through the root proxy's `?url=` parameter on regional API endpoints. The original evidence shows a response from a localhost application, an internal SSH banner exposed through a proxy error, and an external service returning the server's outbound IP. A comparison request to production is rejected with `Host not allowed`.

The report also records CORS origin reflection with credentials and an unauthenticated regional information endpoint. Potential access to databases or other backend services was not demonstrated in the included evidence. AWS credential theft was not demonstrated; the report states that IMDSv2 enforcement mitigated metadata access.

Recommended remediation includes consistent host allowlisting across regional and production instances, blocking private and link-local destinations, requiring authentication for the regional information endpoint, and restricting CORS to trusted origins.

### [Network Management System — Security Assessment](https://1mgr00t90.github.io/reports/nms-pentest-report/)

**Stored and reflected XSS · HTML injection · Client-side security**

A manual grey-box assessment of an internally developed network management interface. The report covers a stored XSS finding in firewall rule comments, related injection paths, outdated JavaScript dependencies, browser hardening, and remediation priorities.

### [Cryptocurrency Threat-Intelligence Platform — Security Assessment](https://1mgr00t90.github.io/reports/cryptosite-vuln-assesment/)

**Broken access control · Rate limiting · Origin exposure**

A manual black-box web and API assessment covering unauthenticated access to paid-tier data, password-reset rate-limit weaknesses, and exposure of a CDN-protected origin. Includes risk analysis, findings, and recommended corrective actions.

## Engineering

### [AI-Assisted SOC Triage Agent](tools/ai-soc-agent/)

A Slack-invoked investigation agent that uses defined read-only tools to retrieve and correlate Microsoft Sentinel and Azure telemetry. Designed to distinguish observed evidence from analysis and leave investigation and response decisions with the analyst.

[Explore the code and technical README](tools/ai-soc-agent/README.md)

## Articles

### [From Pentesting to Security Visibility: Building a SIEM on a Nonprofit Budget](https://1mgr00t90.github.io/articles/from-pentester-to-security-lead/)

An anonymized account of moving from web and API penetration testing into remediation validation, vulnerability management, Microsoft Sentinel detection engineering, incident triage, and AI-assisted security operations at a music education nonprofit.

## Approach

My assessment work emphasizes clear scope and authorization, hands-on validation, repeatable proof of impact, risk-based remediation, and retesting. The reports are written to be useful to both technical teams and stakeholders making remediation decisions.

**Publication note:** Client and infrastructure identifiers are redacted or generalized in public reports. Representative values are identified where used; consult the individual reports for their evidence and limitations.
