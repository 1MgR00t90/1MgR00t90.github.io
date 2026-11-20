# SSRF in Regional API Proxy Endpoints

## Publication note

This is a sanitized portfolio version of a finding documented during testing. Organization names, real domains, public IP addresses, exact timestamps, software versions, distinctive response strings, and secondary endpoint paths have been omitted or generalized. All example domains are placeholders. Response excerpts are normalized illustrations of the recorded behavior, not verbatim responses.

## Summary

The source report documents Server-Side Request Forgery (SSRF) in the URL-fetching functionality of two regional API deployments. A production deployment rejected the same loopback target through a host allowlist, while the regional deployments allowed requests to loopback and an internal network service.

The finding illustrates inconsistent security controls across deployments of the same functionality.

## Vulnerability type

Server-Side Request Forgery (SSRF).

## Affected functionality

A proxy endpoint accepted a user-controlled destination through a URL query parameter. For this publication, the endpoints are represented as:

- `https://region-a-api.example.com/?url=`
- `https://region-b-api.example.com/?url=`

The production comparison endpoint is represented as `https://api.example.com/`.

## Evidence and reproduction

The following examples use placeholder hosts and generalized service ports. They describe the original test sequence and are not instructions to test a live organization.

### 1. Loopback service access

A request to the regional proxy targeted a service bound to the server's loopback interface:

```text
GET /?url=http://127.0.0.1:<internal-http-port>/ HTTP/1.1
Host: region-a-api.example.com
```

The proxy returned an internal application's status response. Application-specific strings and timestamps have been omitted.

### 2. Internal service reachability

A second request targeted an internal network service. The proxy returned a protocol-parsing error containing an SSH banner.

This supports reachability of the service from the proxy. It does not demonstrate SSH authentication, command execution, or compromise of that service. The internal address, exact error text, and software version are omitted.

### 3. External request confirmation

A request to a controlled external HTTP endpoint returned the server's outbound source address. That address and the external test endpoint are omitted.

### 4. Deployment comparison

The equivalent loopback request through the production endpoint returned a host-allowlist rejection:

```text
GET /?url=http://127.0.0.1:<internal-http-port>/ HTTP/1.1
Host: api.example.com
```

The regional and production responses demonstrated a difference in destination validation.

## Impact and evidence limits

**Demonstrated in the source report:**

- Server-side requests to a loopback HTTP service.
- Reachability of an internal service, evidenced by a protocol banner.
- External URL fetching and disclosure of the server's outbound source address.
- Inconsistent destination restrictions across regional and production deployments.

**Potential consequences requiring additional validation:**

- Internal service enumeration through response differences.
- Access to sensitive internal applications or data if reachable services expose them.
- Cloud metadata exposure if the request primitive and metadata protections permit it.

Database access, credential theft, remote code execution, and internal service compromise were not established by the evidence included in the source report. The source describes metadata protections as limiting metadata access; the supplied evidence does not independently verify their configuration.

## Secondary observations

The source also records permissive CORS behavior and an unauthenticated diagnostic response on regional deployments. These observations lack complete reproduction evidence in the supplied report and are not presented here as independently validated findings.

A credentialed CORS exploit would require validation of browser behavior, cookie restrictions, and access to a sensitive response. Public API documentation alone does not establish a vulnerability. Exact diagnostic paths are omitted because the source uses inconsistent names.

## Remediation recommendations

1. Apply a consistent, explicit destination allowlist across all deployments of the proxy.
2. Validate destination schemes, hostnames, resolved addresses, and ports. Restrict the proxy to the destinations required for its business purpose.
3. Reject loopback, private, link-local, and other prohibited destinations for both IPv4 and IPv6, including alternate address representations.
4. Revalidate destinations after DNS resolution and on every redirect, or disable redirects. Account for DNS rebinding.
5. Use network egress controls to prevent the proxy from reaching internal management services and metadata endpoints unless explicitly required.
6. Return generic proxy errors rather than internal response details or service banners.
7. Require appropriate authentication and authorization for diagnostic functions, and restrict credentialed CORS to explicitly trusted origins.
8. Add regression checks across every deployment for allowed destinations, prohibited destinations, redirects, DNS changes, and equivalent IPv6 targets.

## Retest status

Remediation and retest status are not provided in the supplied report.
