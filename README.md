# ArkForge Trust Layer

**ArkForge certifies what your agent executed** — the exact request sent, the exact response received, the exact payment made, and the exact moment it happened. Not intent. Not a log. A cryptographic proof with European legal standing.

Free tier: one curl, instantly autonomous. Pro/Enterprise: subscribe monthly, API key delivered instantly — fully autonomous after that.

## Documentation

- **[User Guide](docs/user-guide.md)** — integration walkthrough, Mode A vs Mode B, code examples, credit management
- **[Quick Reference](docs/quick-reference.md)** — endpoints, chain hash formulas, checklists

## Get started in 30 seconds

### Step 1 — Get a free API key

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/free-signup \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
# → {"api_key": "mcp_free_xxxx...", "email": "you@example.com"}
```

### Step 2 — Make a verified API call

```bash
curl -X POST https://arkforge.fr/trust/v1/proxy \
  -H "X-Api-Key: mcp_free_xxxx..." \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com/v1/run",
       "payload": {"task": "analyze", "text": "hello"}}'
```

ArkForge forwards your request, fingerprints the exchange (SHA-256), signs it (Ed25519), and returns the result with a cryptographic proof.

### Step 3 — Verify

```bash
curl https://arkforge.fr/trust/v1/proof/prf_20260227_110211_a27069
# → full proof JSON: hashes, signature, timestamps, verification status
```

Or open it in a browser — each proof has a public HTML verification page.

---

## Why use it?

**For humans hiring agents:**
- Verify what your agent actually did — call by call, with cryptographic proof
- Your agent routes its LLM and API calls through ArkForge; you get an immutable audit trail: which model was called, exact prompt, exact response, timestamp, cost
- Internal logs are mutable. ArkForge proofs are not.

**For developers and agents:**
- Prove what your agent actually executed — not what it intended
- Attach a verifiable receipt to every API call, automatically
- Add cryptographic trust to any upstream service without modifying it

**For regulated environments (AI Act, DORA, NIS2, eIDAS):**
- Every proof is signed (Ed25519), timestamped (RFC 3161), and anchored in a public immutability log (Sigstore Rekor)
- RFC 3161 timestamps via a pool of WebTrust-certified authorities (FreeTSA → DigiCert → Sectigo)
- Open proof specification ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec)) — any third party can verify a proof without trusting ArkForge

## Features

- **Execution certification** — every API call through ArkForge produces a cryptographic proof of what was sent, received, paid, and when. Immutable after creation.
- **Subscription plans** — Free (500/month, no card), Pro (€29/month, 5,000 proofs), Enterprise (€149/month, 50,000 proofs); opt-in overage billing
- **Proofs** — SHA-256 hash chain per call, publicly verifiable, anchored via RFC 3161 Timestamp Authority
- **Ed25519 signature** — every proof is signed by ArkForge's Ed25519 key, proving origin. Public key served at `GET /v1/pubkey`
- **Sigstore Rekor** — chain hash registered in the Linux Foundation's append-only public transparency log, verifiable by anyone at [search.sigstore.dev](https://search.sigstore.dev)
- **External receipt verification** — attach a Stripe receipt URL to any proxy call; ArkForge fetches, hashes, and parses it independently (see below)
- **API keys** — `mcp_free_*` / `mcp_pro_*` / `mcp_ent_*` / `mcp_test_*` prefixes auto-select plan and Stripe mode
- **Free tier** — 500 proofs/month, no credit card required
- **Agent identity** — optional `X-Agent-Identity` / `X-Agent-Version` headers, mismatch detection across calls
- **Triptyque de la Preuve** — 3-level watermarking on every transaction (see below)
- **Rate limiting** — daily cap (all keys) + monthly quota (Free: 500/month, Pro: 5 000/month, Enterprise: 50 000/month)
- **Overage billing (opt-in)** — Pro/Enterprise keys can opt in to overage billing: proofs beyond the monthly quota are debited from prepaid credits at a lower per-proof rate (€0.01 Pro, €0.005 Enterprise), up to a monthly cap chosen by the user (€5–€100)
- **Email** — welcome + proof receipts via Resend (SMTP relay, DKIM-signed, `noreply@arkforge.fr`)
- **Proof Specification** — open spec with test vectors for independent verification ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec))

## Use cases

### Use case 1 — Agent paying a provider (B2A)

An autonomous agent calls a third-party API and pays for the service. ArkForge certifies the transaction from the agent's side: the exact request sent, the exact response received, the payment evidence, and the timestamp — all bound in a single cryptographic proof. The provider cannot deny delivery; the agent cannot deny the request.

```
Agent → POST /v1/proxy (with payment evidence) → ArkForge → Provider API
                                                       ↓
                                              Signed proof: request + response + payment + timestamp
```

### Use case 2 — Agent proving its own execution to a human client

A human hires an agent to perform tasks. The agent routes its LLM and API calls through ArkForge. The human gets a verifiable audit trail: which model was called, with which exact prompt, what response was returned, at what time, and at what cost. Unlike internal logs, these proofs are cryptographically signed and anchored in a public immutability log — they cannot be altered after the fact.

```
Human client hires agent → agent routes all calls through ArkForge
                                        ↓
                           Immutable audit trail: model + prompt + response + timestamp + cost
                                        ↓
                           Human verifies: "here is exactly what my agent did"
```

This addresses the accountability gap in enterprise agent deployments: teams deploying agents in production today have only mutable internal logs. ArkForge makes agent execution auditable by design — directly relevant to DORA, NIS2, and AI Act traceability requirements.

## Self-hosting

> **Note:** Self-hosted instances provide cryptographic integrity but carry no independent third-party attestation. For proofs verifiable by external parties, use the hosted ArkForge service at [arkforge.fr/trust](https://arkforge.fr/trust).

```bash
# Clone & install
git clone https://github.com/ark-forge/trust-layer.git
cd trust-layer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

# Configure
cp .env.example .env
# Edit .env with your Stripe keys and Resend API key…

# Run
uvicorn trust_layer.app:app --host 0.0.0.0 --port 8100

# Test
pytest tests/ -v
```

## Production Deployment

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRUST_LAYER_BASE_URL` | Yes | — | Public base URL (e.g. `https://arkforge.fr/trust`) |
| `STRIPE_LIVE_SECRET_KEY` | Yes | — | Stripe live secret key (`sk_live_...`) |
| `STRIPE_TEST_SECRET_KEY` | No | — | Stripe test secret key (`sk_test_...`) |
| `STRIPE_TL_WEBHOOK_SECRET` | Yes | — | Stripe webhook signing secret for live events |
| `STRIPE_TL_WEBHOOK_SECRET_TEST` | No | — | Stripe webhook signing secret for test events |
| `SMTP_HOST` | No | `smtp.resend.com` | SMTP server (Resend relay) |
| `SMTP_PORT` | No | `465` | SMTP port (SSL/TLS) |
| `SMTP_LOGIN` | No | `resend` | SMTP auth login (use `resend` for Resend.com) |
| `SMTP_USER` | No | `noreply@arkforge.fr` | From address for outgoing emails |
| `SMTP_PASSWORD` | No | — | SMTP password / Resend API key (`re_...`) |
| `TRUST_LAYER_INTERNAL_SECRET` | No | — | Secret forwarded to upstream as `X-Internal-Secret` header |
| `CORS_ALLOWED_ORIGINS` | No | `https://arkforge.fr,https://www.arkforge.fr` | Comma-separated CORS allowed origins |
| `KEYS_FERNET_KEY_FILE` | No | `/opt/claude-ceo/config/keys_fernet.key` | Path to Fernet key for `api_keys.json` encryption at rest. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. If absent, keys are stored unencrypted (warning logged). |
| `KEYS_FERNET_KEY` | No | — | Fernet key as base64 string (env var alternative to `KEYS_FERNET_KEY_FILE`). Takes precedence over the file. |

### Signing key

An Ed25519 signing key is auto-generated at `.signing_key.pem` on first run. To generate manually:

```bash
python3 -c "from trust_layer.crypto import generate_keypair; print(generate_keypair('.signing_key.pem'))"
```

The public key is served at `GET /v1/pubkey`. **Back up `.signing_key.pem` — losing it means existing proofs cannot be signature-verified.**

### File permissions

```bash
chmod 600 .signing_key.pem .env
chmod 600 /opt/claude-ceo/config/keys_fernet.key   # Fernet key for api_keys.json encryption
chmod 750 data/ proofs/
```

### nginx

```nginx
location /trust/ {
    proxy_pass http://127.0.0.1:8100/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### systemd

```ini
[Unit]
Description=ArkForge Trust Layer
After=network.target

[Service]
User=arkforge
WorkingDirectory=/opt/trust-layer
EnvironmentFile=/opt/trust-layer/.env
ExecStart=/opt/trust-layer/.venv/bin/uvicorn trust_layer.app:app --host 127.0.0.1 --port 8100
Restart=always

[Install]
WantedBy=multi-user.target
```

## Error codes

All error responses use the format `{"error": {"code": "...", "message": "...", "status": N}}`.

| Code | HTTP | Description |
|------|------|-------------|
| `invalid_api_key` | 401 | Missing, invalid, or inactive API key |
| `invalid_target` | 400 | Target URL is not HTTPS, is a private IP, or hostname resolves to a private range |
| `invalid_currency` | 400 | Unsupported currency (only `eur` supported) |
| `invalid_amount` | 400 | Amount below minimum or above maximum |
| `invalid_request` | 400 | Missing required field, invalid JSON, or malformed input |
| `invalid_plan` | 403 | Operation not available on this plan (e.g. free key trying to buy credits) |
| `rate_limited` | 429 | Daily or monthly quota exceeded — if monthly quota, enable overage at `POST /v1/keys/overage` |
| `overage_cap_reached` | 429 | Monthly overage cap reached — increase cap or wait for next month |
| `insufficient_credits` | 402 | Credit balance too low — recharge at `/v1/credits/buy` |
| `insufficient_overage_credits` | 402 | Overage billing active but credit balance is zero — recharge at `/v1/credits/buy` |
| `already_exists` | 409 | A free API key already exists for this email |
| `no_payment_method` | 400 | No payment method linked — use `/v1/keys/setup` first |
| `payment_failed` | 402 | Stripe payment failed |
| `proxy_timeout` | 504 | Target service timed out |
| `service_error` | 502 | Target service returned an error (proof still generated) |
| `not_found` | 404 | Proof or resource not found |
| `internal_error` | 500 | Internal server error |

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/pricing` | Pricing and limits |
| `POST` | `/v1/proxy` | Proxied API call (charge + forward + proof) |
| `POST` | `/v1/keys/setup` | Subscribe to Pro or Enterprise monthly plan via Stripe Checkout |
| `POST` | `/v1/keys/portal` | Open Stripe Billing Portal (update card, view invoices) |
| `POST` | `/v1/keys/overage` | Enable/disable overage billing (Pro/Enterprise only) |
| `GET` | `/v1/keys/overage` | Get current overage settings |
| `POST` | `/v1/webhooks/stripe` | Stripe webhook receiver |
| `GET` | `/v1/usage` | Usage stats for a key |
| `GET` | `/v1/proof/{proof_id}` | Retrieve and verify proof (JSON or HTML — see content negotiation) |
| `GET` | `/v/{proof_id}` | Short URL — 302 redirect to `/v1/proof/{proof_id}` |
| `GET` | `/v1/proof/{proof_id}/tsr` | Download RFC 3161 timestamp response file |
| `POST` | `/v1/credits/buy` | Buy prepaid credits via Stripe Checkout (returns checkout URL) |
| `GET` | `/v1/pubkey` | ArkForge's Ed25519 public key for signature verification |
| `GET` | `/v1/agent/{agent_id}/reputation` | Public reputation score (0-100) for an agent |
| `POST` | `/v1/disputes` | Flag a proof as contested *(infrastructure only — resolution not yet implemented)* |
| `GET` | `/v1/agent/{agent_id}/disputes` | Dispute history for an agent *(infrastructure only)* |

## Core flow — POST /v1/proxy

```json
{
  "target": "https://example.com/api/scan",
  "method": "POST",
  "payload": {"repo_url": "https://github.com/owner/repo"},
  "description": "EU AI Act compliance scan"
}
```

**Optional body field — external payment evidence:**

```json
{
  "target": "https://provider.com/api/endpoint",
  "payload": {"task": "analyze"},
  "provider_payment": {
    "type": "stripe",
    "receipt_url": "https://pay.stripe.com/receipts/payment/CAcaFwo..."
  }
}
```

When `provider_payment.receipt_url` is provided, ArkForge fetches the receipt directly from the PSP, hashes the raw content (SHA-256), parses key fields (amount, currency, status, date), and includes the `receipt_content_hash` in the proof's chain hash. The receipt hash is the proof — it remains valid even if parsing fails.

Currently supported PSPs: **Stripe** (`pay.stripe.com`, `receipt.stripe.com`). The parser architecture is extensible — adding a new PSP requires implementing a single `ReceiptParser` subclass.

**Optional body field — forwarded headers (`extra_headers`):**

Headers that Trust Layer will forward to the target API alongside the request. Use this when the target requires authentication or custom headers.

```json
{
  "target": "https://api.github.com/repos/owner/repo/issues/5/comments",
  "method": "POST",
  "payload": {"body": "Automated analysis complete."},
  "extra_headers": {
    "Authorization": "token ghp_xxx",
    "Accept": "application/vnd.github+json"
  }
}
```

**Constraints:**
- Maximum **10 headers**
- Keys and values must be **strings**
- Values must not exceed **4096 characters**
- The following headers are **silently dropped** (security):
  `Host`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Content-Length`, `Content-Type`, `X-Internal-Secret`

`Content-Type` is always `application/json` — it cannot be overridden via `extra_headers`.

**Optional headers:**

| Header | Description |
|--------|-------------|
| `X-Agent-Identity` | Agent's self-declared name (e.g. `my-agent-v1`) |
| `X-Agent-Version` | Agent's version string (e.g. `2.0.3`) |

These are stored in the proof and shadow profile. If the same API key sends a different identity, all subsequent proofs are flagged `identity_consistent: false`.

**Response includes:**
- `proof.spec_version` — proof format version (`1.1` without receipt, `2.0` with receipt — see [proof-spec](https://github.com/ark-forge/proof-spec))
- `proof.certification_fee` — Stripe transaction ID, credit deduction, receipt URL
- `proof.hashes` — SHA-256 of request, response, and chain
- `proof.arkforge_signature` — Ed25519 signature of the chain hash (format: `ed25519:<base64url>`)
- `proof.arkforge_pubkey` — ArkForge's Ed25519 public key used for signing
- `proof.upstream_timestamp` — upstream service's `Date` header (if present)
- `proof.provider_payment` — external receipt verification (if `provider_payment` was provided in request, see below)
- `proof.parties.agent_identity` / `agent_version` — declared identity (if provided)
- `proof.identity_consistent` — `true` / `false` / `null` (consistency check)
- `proof.verification_url` — public URL to verify the proof
- `proof.timestamp_authority` — TSA status, provider, download URL, and `tsr_base64` (after background processing)
- `service_response` — upstream API response
- `service_response.body._arkforge_attestation` — digital stamp (Level 1, see below)

**Response headers (Level 2 — Ghost Stamp):**

| Header | Value | Description |
|--------|-------|-------------|
| `X-ArkForge-Proof` | `https://.../v1/proof/prf_...` | Full verification URL (backward compat) |
| `X-ArkForge-Verified` | `true` / `false` | `true` if upstream returned 2xx/3xx, `false` on error |
| `X-ArkForge-Proof-ID` | `prf_...` | Proof ID for programmatic use |
| `X-ArkForge-Trust-Link` | `https://.../v/prf_...` | Short shareable link |

## Triptyque de la Preuve

Every transaction carries the ArkForge mark at 3 levels — for machines, for infrastructure, and for humans.

### Level 1 — Digital Stamp (JSON body)

On successful proxy calls, an `_arkforge_attestation` field is injected into `service_response.body`:

```json
{
  "_arkforge_attestation": {
    "id": "prf_20260225_204347_098610",
    "seal": "https://arkforge.fr/trust/v1/proof/prf_20260225_204347_098610",
    "status": "VERIFIED_TRANSACTION",
    "msg": "Payment confirmed, execution anchored."
  }
}
```

The attestation is injected **after** hashing — the chain hash is not affected. Skipped on error responses and non-JSON bodies.

### Level 2 — Ghost Stamp (HTTP headers)

Every proxy response includes 4 `X-ArkForge-*` headers (see table above). These are visible to monitoring tools, API gateways, and any middleware in the chain — without parsing the body.

### Level 3 — Visual Stamp (HTML proof page)

`GET /v1/proof/{proof_id}` supports content negotiation:

- `Accept: text/html` → self-contained HTML page with a colored verification badge
- `Accept: application/json` or no Accept header → JSON (backward compatible)

Badge colors:
- **Green** (`#22c55e`) — integrity verified, certified timestamp obtained
- **Orange** (`#f59e0b`) — integrity verified, timestamp pending
- **Red** (`#ef4444`) — integrity check failed

The proof page shows 3 independent witnesses:
- **Ed25519 Signature** — proves ArkForge origin (green if signed, grey if not)
- **RFC 3161 Timestamp** — issued by the first available TSA in the pool: FreeTSA → DigiCert → Sectigo (green when verified, orange when pending). The `timestamp_authority.provider` field records which TSA was used.
- **Sigstore Rekor** — chain hash anchored in the Linux Foundation's append-only public log (green when registered, grey when pending)

All proofs (Free and Pro) have 3 witnesses. Pro proofs additionally record the Stripe credit purchase receipt for audit.

**Short URL:** `GET /v/{proof_id}` → 302 redirect to the full proof endpoint. Cacheable (24h).

## Provider payment (Mode B)

When an agent pays a provider directly — outside ArkForge, agent-to-provider — it can attach the Stripe receipt URL as `provider_payment` to the proxy call. ArkForge fetches the receipt, hashes the raw content, and binds it to the proof. **ArkForge does not process or intermediate this payment.**

The proof page labels this section "Provider payment" with the note *"Paid directly from agent to provider — not processed by ArkForge"* to distinguish it from the ArkForge certification fee (0.10 EUR).

### How it works

1. Client includes `provider_payment.receipt_url` in `POST /v1/proxy`
2. ArkForge validates the URL (HTTPS only, whitelisted PSP domains)
3. ArkForge fetches the receipt page directly from the PSP
4. Raw content is hashed (SHA-256) — this is the immutable proof
5. Key fields are parsed (amount, currency, status, date)
6. `receipt_content_hash` is included in the chain hash formula
7. The `provider_payment` object is stored in the proof

### Provider payment in the proof JSON

```json
{
  "provider_payment": {
    "type": "stripe",
    "receipt_url": "https://pay.stripe.com/receipts/payment/...",
    "receipt_fetch_status": "fetched",
    "receipt_content_hash": "sha256:a1b2c3...",
    "parsing_status": "success",
    "parsed_fields": {"amount": 49.99, "currency": "usd", "status": "paid", "date": "February 28, 2026"},
    "verification_status": "fetched"
  }
}
```

| Field | Description |
|-------|-------------|
| `type` | PSP type (`stripe`, or as declared by client) |
| `receipt_url` | Original receipt URL |
| `receipt_fetch_status` | `fetched` (success) or `failed` (timeout, HTTP error, invalid domain) |
| `receipt_content_hash` | SHA-256 of the raw receipt bytes — included in chain hash |
| `parsing_status` | `success`, `failed`, or `not_attempted` |
| `parsed_fields` | Extracted fields (amount, currency, status, date) — null if parsing failed |
| `verification_status` | `fetched` (independently verified) or `failed` |
| `receipt_fetch_error` | Error details (only present on failure) |

### Supported PSPs

| PSP | Domains | Parser |
|-----|---------|--------|
| **Stripe** | `pay.stripe.com`, `receipt.stripe.com` | Regex-based (amount, currency, status, date) |

The parser architecture is extensible. Adding a new PSP requires subclassing `ReceiptParser` and calling `register_parser()` — no changes to the proxy, proof, or API code.

### Security

- **SSRF protection** — only whitelisted PSP domains are fetched (whitelist auto-built from registered parsers)
- **HTTPS only** — HTTP URLs are rejected
- **Size limit** — max 500 KB response, max 3 redirects, 10s timeout
- **Hash immutability** — the `receipt_content_hash` is in the chain hash formula, so modifying the receipt after the fact breaks verification

## Chain hash algorithm

The chain hash binds every element of a transaction into a single verifiable seal. The formula is public and deterministic — anyone can recompute it:

```
chain_hash = SHA256(request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller [+ upstream_timestamp] [+ receipt_content_hash])
```

Where:
- `request_hash` = SHA-256 of the canonical JSON request (sorted keys, no whitespace)
- `response_hash` = SHA-256 of the canonical JSON response
- `payment_intent_id` = Stripe Payment Intent ID (e.g. `pi_3T4ovu...`) or `free_tier` for free plan proofs
- `timestamp` = ISO 8601 UTC (e.g. `2026-02-25T20:43:45Z`)
- `buyer_fingerprint` = SHA-256 of the API key
- `seller` = target domain (e.g. `example.com`)
- `upstream_timestamp` = upstream service's `Date` header (included **only** when present in the proof JSON)
- `receipt_content_hash` = SHA-256 of the raw receipt bytes (included **only** when `provider_payment.receipt_content_hash` is present — strip the `sha256:` prefix before concatenation)

All values are concatenated as raw strings (no separator) before hashing. Canonical JSON uses `json.dumps(data, sort_keys=True, separators=(",", ":"))`.

**Spec versions:** proofs without `provider_payment` use spec version `1.1`. Proofs with a `receipt_content_hash` use spec version `2.0`.

**Backward compatibility:** optional fields (`upstream_timestamp`, `receipt_content_hash`) are only included in the chain input when present in the proof JSON. Older proofs (v1.1) verify with the same formula by omitting those fields.

## Digital signature

Every proof's chain hash is signed with ArkForge's Ed25519 private key. This proves the proof was issued by ArkForge (origin authentication), not just that it is internally consistent (integrity).

- **Algorithm:** Ed25519
- **Format:** `ed25519:<base64url_without_padding>`
- **What is signed:** the chain hash hex string (UTF-8 encoded)
- **Public key:** available at `GET /v1/pubkey` and below

**Current public key:**

```
ed25519:ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY
```

**What the signature guarantees:** integrity of all fields covered by the chain hash (request, response, payment, timestamp, buyer, seller, upstream_timestamp if present, receipt_content_hash if present).

**What the signature does NOT cover:** `views_count`, `identity_consistent`, and other informational/mutable metadata.

## Independent verification

You can verify any proof without ArkForge's code. Given a proof JSON:

```bash
# 1. Extract the components
REQUEST_HASH=$(echo -n "$PROOF" | jq -r '.hashes.request' | sed 's/sha256://')
RESPONSE_HASH=$(echo -n "$PROOF" | jq -r '.hashes.response' | sed 's/sha256://')
PAYMENT_ID=$(echo -n "$PROOF" | jq -r '.certification_fee.transaction_id')  # 'free_tier' for free plan
TIMESTAMP=$(echo -n "$PROOF" | jq -r '.timestamp')
BUYER=$(echo -n "$PROOF" | jq -r '.parties.buyer_fingerprint')
SELLER=$(echo -n "$PROOF" | jq -r '.parties.seller')
UPSTREAM=$(echo -n "$PROOF" | jq -r '.upstream_timestamp // empty')
RECEIPT_HASH=$(echo -n "$PROOF" | jq -r '.provider_payment.receipt_content_hash // empty' | sed 's/sha256://')

# 2. Recompute the chain hash
COMPUTED=$(echo -n "${REQUEST_HASH}${RESPONSE_HASH}${PAYMENT_ID}${TIMESTAMP}${BUYER}${SELLER}${UPSTREAM}${RECEIPT_HASH}" | sha256sum | cut -d' ' -f1)

# 3. Compare with the proof's chain hash
EXPECTED=$(echo -n "$PROOF" | jq -r '.hashes.chain' | sed 's/sha256://')
[ "$COMPUTED" = "$EXPECTED" ] && echo "VERIFIED" || echo "TAMPERED"
```

If the chain hash matches, no field in the proof was altered after creation. For Pro proofs, the Stripe Payment Intent ID can be independently verified on Stripe's dashboard or API. For Free proofs, the payment_intent_id is `free_tier`. For proofs with receipt evidence, the `receipt_content_hash` binds the external receipt to the proof — modifying the receipt after the fact invalidates the chain hash.

To also verify the Ed25519 signature, use the public key from `GET /v1/pubkey` (or the value above) with any Ed25519 library. The signed message is the chain hash hex string.

## Reputation Score

Every agent gets a deterministic reputation score (0-100) based on their proof history. No ML, no reviews — only factual data from proofs. The formula is public and auditable by any third party from the proof history alone.

### Formula

```
score = floor(success_rate × confidence) − penalties
```

| Volume | Confidence factor | Example (100% success) |
|--------|------------------|------------------------|
| 0–1 proofs | 0.60 (provisional) | → 60 |
| 2–4 proofs | 0.75 | → 75 |
| 5–19 proofs | 0.85 | → 85 |
| 20+ proofs | 1.00 (full confidence) | → 100 |

`success_rate = succeeded_proofs / total_proofs × 100`

### Penalty

- **Identity mismatch** — −15 points if the agent changed its declared identity (`X-Agent-Identity` header)

### Get an agent's reputation

```bash
curl https://arkforge.fr/trust/v1/agent/{agent_id}/reputation
# → {
#     "reputation_score": 85,
#     "scoring": {
#       "success_rate": 100.0,
#       "confidence": 0.85,
#       "formula": "floor(success_rate × confidence) − penalties"
#     },
#     "signature": "ed25519:...",
#     ...
#   }
```

The score is signed with ArkForge's Ed25519 key — verifiable via `/v1/pubkey`. Cached for 1 hour, recomputed lazily.

## Dispute System *(infrastructure only — resolution not yet available)*

> **Note:** The dispute endpoints exist at the infrastructure level (flagging, history, proof markers) but **the resolution logic is not yet implemented**. Filing a dispute records it on the proof but does not trigger any arbitration or reputation impact. Do not rely on this system for live dispute resolution — see the [Roadmap](ROADMAP.md#dispute-protocol-under-design) for the planned design.

ArkForge records what happened. The proof is the primary evidence in any dispute — it cannot be altered after creation (any modification invalidates the chain hash). In case of a dispute:

- The **chain hash** proves the exact request, response, payment, and timestamp — none can be altered
- The **receipt content hash** (if present) proves the payment receipt content at the time of the call
- The **Ed25519 signature** proves ArkForge recorded it, not one of the parties
- The **Sigstore Rekor entry** anchors the chain hash in an independent public log

Bring this proof to your preferred dispute resolution channel (payment chargeback, platform arbitration, legal). The proof speaks for itself regardless of who holds it.

## Architecture

```
Agent Client
    |
    v
Trust Layer (/v1/proxy)
    |--- 1. Validate API key + rate limit
    |--- 2. Check monthly quota (all plans) — if quota exhausted and overage enabled, deduct overage credit; else 429
    |--- 2b. Deduct overage credit (Pro: 0.01 EUR/proof, Enterprise: 0.005 EUR/proof — opt-in only) or 0 for Free
    |--- 3. Fetch external receipt from PSP (if provider_payment provided)
    |--- 4. Forward request to upstream API
    |--- 5. Hash request + response + receipt (SHA-256 chain)
    |--- 6. Store proof, return response immediately
    |--- 7. Background: RFC 3161 timestamp + email receipt
    |
    v
Upstream API (any HTTPS endpoint)
```

**No database.** Proofs are stored as immutable JSON files on disk — one file per transaction (`proofs/{proof_id}.json`). No SQL, no edits, no deletions. Once written, a proof can only be read. This guarantees that proofs cannot be retroactively altered.

**Encryption at rest.** The API key database (`data/api_keys.json`) is encrypted at rest with AES-128 (Fernet / AES-128-CBC + HMAC-SHA256). Proof files contain only SHA-256 hashes — no payload content. Proofs are retained for 7 years from creation for dispute resolution purposes.

**RFC 3161 timestamps** use a pool of 3 public TSA servers tried in order — first success wins:

1. **FreeTSA.org** (primary) — free community TSA, no contractual SLA
2. **DigiCert** (`timestamp.digicert.com`) — WebTrust-certified CA infrastructure
3. **Sectigo** (`timestamp.sectigo.com`) — WebTrust-certified CA infrastructure

If FreeTSA is unavailable, DigiCert takes over automatically within the same background task. The `timestamp_authority.provider` field in the proof records which TSA was actually used. The pool is configured via env vars (`TSA_PRIMARY_URL`, `TSA_SECONDARY_URL`, `TSA_TERTIARY_URL`). If all TSA servers fail, the proof remains valid via Ed25519 + Sigstore Rekor anchoring.

> **eIDAS-qualified timestamps (QTSP):** For legal proceedings requiring a qualified electronic timestamp under eIDAS Regulation (e.g. Article 41 evidentiary value), ArkForge supports injecting a QTSP-certified endpoint as the primary TSA — no code change required, configuration only (`TSA_PRIMARY_URL`, `TSA_CA_FILE`, `TSA_CERT_FILE`). The QTSP provider's certificates must be supplied. Available as a custom arrangement on top of any plan. [Contact us](mailto:contact@arkforge.fr) for pricing and setup.

## New client onboarding

### 1. Get a free key (instant, no card)

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/free-signup \
  -H "Content-Type: application/json" \
  -d '{"email": "client@example.com"}'
# Returns: {"api_key": "mcp_free_...", "plan": "free", "limit": "500 proofs/month"}
```

### 2. Subscribe to Pro or Enterprise

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "client@example.com", "plan": "pro"}'
# Returns: {"checkout_url": "https://checkout.stripe.com/...", "plan": "pro"}
```

Open `checkout_url` in a browser — enter a card and confirm. Stripe activates the subscription and fires a webhook: Trust Layer creates the API key (`mcp_pro_...` or `mcp_ent_...`) and emails it to the client.

For test mode, add `"mode": "test"` and use Stripe test card `4242 4242 4242 4242`. Use `"plan": "enterprise"` for the Enterprise plan.

### 3. Use the proxy

```bash
curl -X POST https://arkforge.fr/trust/v1/proxy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "X-Agent-Identity: my-agent" \
  -H "X-Agent-Version: 1.0.0" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://arkforge.fr/api/v1/scan-repo",
    "payload": {"repo_url": "https://github.com/owner/repo"}
  }'
```

Calls within the monthly quota (5,000 for Pro, 50,000 for Enterprise) are included in the subscription — no per-call charge. Beyond the quota: HTTP 429 by default, or overage billing from prepaid credits (opt-in, 0.01 EUR/proof for Pro, 0.005 EUR/proof for Enterprise).

### 3b. Manage subscription / view invoices

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/portal \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{}'
# Returns: {"portal_url": "https://billing.stripe.com/...", ...}
```

Open `portal_url` to update your payment method, download invoices, or cancel the subscription.

### 3c. Buy overage credits (optional, opt-in only)

```bash
curl -X POST https://arkforge.fr/trust/v1/credits/buy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 10.00}'
# Returns: {"credits_added": 10.0, "balance": 10.0, "proofs_available": 1000, ...}
```

Overage credits are only consumed if you explicitly enable overage billing (`POST /v1/keys/overage`). The saved card is charged off-session — no browser required.

## Credits (overage only)

Pro and Enterprise subscriptions include a monthly proof quota. Prepaid credits are **only used for opt-in overage billing** — not for standard calls within the quota.

**Overage pricing (opt-in):** when the monthly quota is exhausted, Pro keys can continue at **0.01 EUR/proof** and Enterprise keys at **0.005 EUR/proof**, both debited from prepaid credits up to a monthly cap (€5–€100). Overage billing is disabled by default — activate it at `POST /v1/keys/overage`.

### Buy overage credits

```bash
curl -X POST https://arkforge.fr/trust/v1/credits/buy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 10.00}'
# Returns: {"credits_added": 10.0, "balance": 10.0, "proofs_available": 1000, ...}
```

The saved card is charged off-session — no browser required. Credits are added immediately. Minimum purchase: 1.00 EUR.

### Check balance and quota

```bash
curl https://arkforge.fr/trust/v1/usage \
  -H "X-Api-Key: mcp_pro_..."
# Returns: {"plan": "pro", "monthly": {"used": 1250, "limit": 5000, "remaining": 3750}, "credit_balance": 10.0}
```

### Email alerts

- **80% monthly quota** consumed → quota alert
- **Overage started** — first overage proof of the month (if overage enabled)
- **Overage 80% cap** consumed → overage alert
- **Overage cap reached** → requests blocked (HTTP 429) + alert
- **Low balance** (< 1.00 EUR) → recharge reminder (24h cooldown)
- **Credits exhausted** when a call is rejected (402) → includes recharge curl command

Free keys (`mcp_free_*`) do not use credits — they have a monthly quota of 500 proofs at no cost.

## Plans and API key prefixes

| Prefix | Plan | Monthly price | Quota | Overage (opt-in) | Witnesses |
|--------|------|---------------|-------|-----------------|-----------|
| `mcp_free_*` | Free | Free | 500 proofs/month | Not available | 3 (Ed25519, RFC 3161 TSA, Sigstore Rekor) |
| `mcp_pro_*` | Pro | €29/month | 5,000 proofs/month | 0.01 EUR/proof (€5–€100 cap) | 3 (Ed25519, RFC 3161 TSA, Sigstore Rekor) |
| `mcp_ent_*` | Enterprise | €149/month | 50,000 proofs/month | 0.005 EUR/proof (€5–€100 cap) | 3 (Ed25519, RFC 3161 TSA, Sigstore Rekor) |
| `mcp_test_*` | Test | Stripe test mode | 100 proofs/day | Not available | 3 (Ed25519, RFC 3161 TSA, Sigstore Rekor) |

The proxy auto-selects the right plan, witnesses, and rate limits based on the API key prefix. Free tier skips Stripe entirely (no credit card required). Pro and Enterprise keys are created automatically after Stripe subscription checkout. Test mode uses Stripe test keys (card `4242 4242 4242 4242`).

Overage billing is **disabled by default** for all plans. Pro and Enterprise keys can opt in via `POST /v1/keys/overage` with a monthly cap of their choice (€5–€100). No overage charges are applied without explicit consent.

### Custom arrangements

For enterprises with specific regulatory requirements:

| Requirement | Solution |
|------------|----------|
| eIDAS-qualified timestamps (QTSP) | Supported via custom TSA config — not included in standard plans. [Contact us](mailto:contact@arkforge.fr) |
| On-premise deployment | Self-host with your own signing key and TSA pool — see Self-hosting section |
| Volume above 50,000 proofs/month | Negotiated contract — [contact us](mailto:contact@arkforge.fr) |

## Security

### SSRF protection

The proxy endpoint only forwards to `https://` targets. Private and reserved IP ranges are blocked at validation time (before any rate limit check or DNS resolution):

- RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`, `::1/128`
- Link-local / cloud metadata: `169.254.0.0/16` (AWS/GCP/Azure IMDS), `fe80::/10`
- CGNAT: `100.64.0.0/10` (RFC 6598)
- IPv4-mapped IPv6: `::ffff:0:0/96`
- 6to4 tunneling: `2002::/16`
- IPv6 unique local: `fc00::/7`

A DNS rebinding guard resolves hostnames at request time (after syntactic validation) and re-checks every resolved address against the blocklist.

### Network exposure

Uvicorn **must** bind to `127.0.0.1`, not `0.0.0.0`. The systemd template above enforces this. Binding to `0.0.0.0` exposes uvicorn directly (no TLS, no rate limiting, no nginx security headers). nginx proxies `https://your-domain/trust/` → `http://127.0.0.1:8100/` and is the only public entry point.

Verify after any deployment:

```bash
ss -tlnp | grep 8100
# Expected: 127.0.0.1:8100   (not 0.0.0.0:8100)
```

### Dependency CVE scanning

```bash
pip install pip-audit
pip-audit   # scans installed packages against known CVEs
```

Run after any `pip install` or dependency update.

### Security smoke test

A full security smoke test (`scripts/security_smoke_test.py`) covers 55 checks: auth bypass, SSRF vectors, input validation, path traversal, webhook replay, information disclosure, and method restrictions. Run it against any deployment:

```bash
python3 scripts/security_smoke_test.py --url https://arkforge.fr/trust --key mcp_free_xxx
```

All 55 checks pass on the current production deployment.

### Conformance testing

The chain hash algorithm and proof structure are defined in the [ArkForge Proof Specification](https://github.com/ark-forge/proof-spec). The Trust Layer includes conformance tests that validate against the spec's test vectors:

```bash
pytest tests/test_spec_conformance.py -v
```

If a test fails, either the spec or the implementation has drifted. This ensures any third-party verifier produces identical results.

## ArkForge ecosystem

The Trust Layer is one piece of a complete agent-to-agent transaction cycle:

```
Agent Client  →  Trust Layer  →  Service (e.g. EU AI Act Scanner)
   pays            certifies         delivers
```

| Component | Description | Repo |
|-----------|-------------|------|
| **Trust Layer** | Certifying proxy — billing, proof chain, verification | [ark-forge/trust-layer](https://github.com/ark-forge/trust-layer) |
| **MCP EU AI Act** | Compliance scanner — the first service sold through ArkForge | [ark-forge/mcp-eu-ai-act](https://github.com/ark-forge/mcp-eu-ai-act) |
| **Proof Spec** | Open specification + test vectors for the proof format | [ark-forge/proof-spec](https://github.com/ark-forge/proof-spec) |
| **Agent Client** | Autonomous buyer — proof-of-concept of a non-human customer | [ark-forge/arkforge-agent-client](https://github.com/ark-forge/arkforge-agent-client) |

See a live proof: [example transaction](https://arkforge.fr/trust/v/prf_20260303_161853_4d0904)

Currently running with ArkForge-operated services. Third-party provider onboarding coming soon — see **[ROADMAP.md](ROADMAP.md)** for the multi-witness certification architecture.

Building a service you want to make verifiable? [Get in touch](mailto:contact@arkforge.fr).

## Live deployment

Running at **https://arkforge.fr/trust/v1/health**

## License

MIT — see [LICENSE](LICENSE).
