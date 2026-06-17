# Compliance boundaries

SecAgent is a **defensive** tool: it evaluates assets the customer is
authorized to scan. It is not a pen-test service, an exploit tool, or an
internet-wide scanner.

## Four defense lines

1. **Authorization** — no scan runs without a verified token whose scope
   contains the target. (See AUTHORIZATION.md.)
2. **Blocklist** — even with authorization, government/military TLDs, known
   CII, and private/internal IPs are refused with `COMPLIANCE_BLOCK`.
3. **Data minimization** — findings auto-expire after `finding_ttl_days`
   (default 90). Secret-leak findings are stored masked, never plaintext.
4. **Audit** — every call (executed or refused) is written to an append-only,
   hash-chained log for compliance review and abuse detection.

## Customer responsibilities

- Ensure every authorized scope is owned by you or your organization.
- Do not use SecAgent against unauthorized targets. Violations terminate the
  account and may carry legal consequences.

## Product responsibilities

- Maintain the blocklist.
- Never actively exploit a vulnerability (Nuclei detects, does not exploit).
- Provide audit logs for compliance review.
