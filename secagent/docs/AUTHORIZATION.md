# Authorization

SecAgent never scans a target without proof the customer owns it.

## Register a scope

```bash
secagent authz add --domain acme.com
```

The token is **unverified** until ownership is proven.

## Prove ownership (3 methods)

1. **DNS TXT** — add a TXT record:
   `_secagent-verify.acme.com TXT "verify=<token>"`
2. **File** — serve `<token>` at `https://acme.com/.well-known/secagent-verify`
3. **Cert/WHOIS** — registrant subject matches the customer identity

> **M1 note:** M1's CLI `authz verify` records the method you used; it does not
> itself fetch DNS/HTTP (that probing is a small follow-up). Run the proof
> yourself, then call `verify`.

After proof:

```bash
secagent authz verify auth_xxx --method dns_txt
```

## Scope semantics

| Type | Example | Matches |
|---|---|---|
| domain | acme.com | acme.com, *.acme.com |
| ip | 203.0.113.10 | exact |
| cidr | 203.0.113.0/24 | any in range |
| repo | github.com/acme | github.com/acme/* |
| email | a@acme.com | exact |
