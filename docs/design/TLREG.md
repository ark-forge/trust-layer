# TLREG: free API key delivered by email only, with address confirmation

Status: design note (R2), not implemented. Follows TLCOSE-S.

## Problem

`POST /api/register` returns the new `api_key` in the JSON body. Anyone can type any address and receive a key bound to it
without owning the mailbox: quota farming by address, mail bombing of third parties, no proof of ownership. The
"already exists" branch already mails the key and no longer returns it; the "new key" branch does not.

## Best known

Standard double opt-in used by registries issuing tokens by mail (npm/PyPI email verification, Sigstore OIDC email claim):
no credential is issued before the address is proven. We match it; nothing here claims to go beyond.

## Design

1. `POST /api/register {email}`: validate, rate limit as today, store a pending record
   `{email_hash, token_hash (sha256 of 32-byte random), expires_at = now + 24h}` in Redis (TTL 24h, key `reg_pending:{token_hash}`),
   mail a confirmation link `https://trust.arkforge.tech/v1/register/confirm?token=...`. Response: `202 {"status":"pending_confirmation"}`,
   identical whether the address is new or already has a key (no account enumeration).
2. `POST /v1/register/confirm {token}` (GET renders a one-button page that POSTs, so mail scanners prefetching links do not
   consume the token): consume the token atomically (Redis GETDEL), create the key if none exists for the address, mail the key,
   return `{"status":"confirmed"}` without the key. Existing key: resend it.
3. Per-address cap: at most 3 pending mails per address per 24h (counter in Redis), in addition to the per-IP cap.
4. Logs: salted hash of address only (reuse `TL_METRICS_SALT` helpers), never the address or the token.
5. Funnel events: `register_completion` and `signup_attributed` move to the confirm step; add `register_requested`.
6. CLI `mcp-eu-ai-act`: after `/api/register`, print "check your mailbox and confirm", stop expecting `api_key` in the response;
   keep reading `already_existed` for backward compatibility during one release.

## Out of scope

Salting `proof_abuse:{ip}` and `client_ip_hash`, `GET /trial` redirect: separate tickets.

## Tests (red first)

- register response never contains `api_key`, for new and existing addresses, same shape for both.
- no key exists in storage before confirm; exactly one after.
- token single-use, expires after 24h, wrong token = 400 with no oracle.
- GET confirm does not consume the token; POST does.
- 4th request for one address in 24h sends no mail.
- no clear address or token in logs (caplog).
- update `tests/test_free_guard.py` and `tests/test_funnel_metrics.py` call sites.

## Risks

Mail deliverability becomes a hard dependency of onboarding (already true for key delivery). Breaking change for clients that read
`api_key` from the response: announced in CHANGELOG, major-visible in the CLI.
