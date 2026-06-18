# Authorization

SecAgent **never** scans a target without proof the customer owns it. This is
defense line 1 (spec §4.1) and it is the single most important compliance
control in the product.

> **Critical:** authorization registration happens on the CLI — it is **never**
> exposed as an MCP tool. The agent only ever *receives* a token; it cannot
> *mint* one. This prevents "verbal authorization to scan someone else's asset."

## Register a scope

```bash
secagent authz add --domain acme.com --note "customer onboarding"
# => token: auth_AbCdEf1234...
```

The token is **unverified** until ownership is proven. An unverified token
returns `NOT_AUTHORIZED` on every tool call — this is intentional.

## Prove ownership (3 methods, pick one)

### Method 1 — DNS TXT (recommended)

Add a TXT record at a verification subdomain:

```
_scan-verify.acme.com.  IN  TXT  "verify=auth_AbCdEf1234..."
```

Wait for DNS propagation (usually seconds to minutes), then:

```bash
secagent authz verify auth_AbCdEf1234... --method dns_txt
```

### Method 2 — File verification

Serve the token at a well-known URL:

```
https://acme.com/.well-known/scan-auth
```

The file body must contain exactly the token string. Then:

```bash
secagent authz verify auth_AbCdEf1234... --method file
```

### Method 3 — Certificate / WHOIS match

The domain's SSL certificate subject or WHOIS registrant matches the customer
identity. This is manual and only used when DNS/file aren't possible:

```bash
secagent authz verify auth_AbCdEf1234... --method cert
```

> **M1 note:** the CLI `authz verify` records the method you used and marks
> the token verified. It does not itself fetch DNS/HTTP (that network probing
> is a follow-up). Run the proof yourself, then call `verify`.

## Scope semantics

| Type | Example | Matches | Used by |
|---|---|---|---|
| `domain` | `acme.com` | `acme.com`, `*.acme.com` | ① ② ③ ④ ⑥ |
| `ip` | `203.0.113.10` | exact | ② ③ |
| `cidr` | `203.0.113.0/24` | any IP in range | ② ③ |
| `repo` | `github.com/acme` | `github.com/acme/*` | ⑤ |
| `email` | `a@acme.com` | exact | ④ |

The scope check is a suffix match for domains (`sub.acme.com` is in scope of
`acme.com`), an exact match for IPs/emails, a CIDR containment for CIDR, and
a prefix match for repos.

## Manage authorizations

```bash
# List all tokens (shows verified status)
secagent authz list

# Verify a token
secagent authz verify auth_xxx --method dns_txt
```

## What happens on a tool call

Every MCP tool call includes an `authz_token`. The compliance gate checks
(fail-fast order):

1. **Token exists and is verified** → else `NOT_AUTHORIZED`
2. **Target within token scope** → else `NOT_AUTHORIZED`
3. **Target not on blocklist** → else `COMPLIANCE_BLOCK` (even if in scope)
4. **Quota available** → else `RATE_LIMITED` (checked at commit, after the tool runs)

All outcomes — pass or refuse — are written to the append-only, hash-chained
audit log (defense line 4).

## Token security

- Tokens are opaque (`auth_` + 22 URL-safe chars).
- Store them like passwords — anyone with the token can scan within its scope.
- There is no token revocation CLI in the MVP; rotate by issuing a new token
  and deleting the old row from the DB (or just let quota deplete).
- Tokens are passed in MCP tool arguments, not HTTP headers (MVP is stdio
  only, so they never leave the local process).
