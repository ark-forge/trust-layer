# ArkForge Trust Layer

Add verifiable execution to any API call. One signup, one curl.

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

- Prove what your agent actually did
- Attach prepaid credits to execution
- Create audit-ready API calls
- Add trust without modifying existing services

## Features

- **Proxy** — forwards requests to upstream APIs, meters usage, creates proof
- **Prepaid credits** — buy credits via Stripe Checkout, deducted per proof (0.10 EUR/proof)
- **Proofs** — SHA-256 hash chain per call, publicly verifiable, anchored via RFC 3161 Timestamp Authority
- **Ed25519 signature** — every proof is signed by ArkForge's Ed25519 key, proving origin. Public key served at `GET /v1/pubkey`
- **External receipt verification** — attach a Stripe receipt URL to any proxy call; ArkForge fetches, hashes, and parses it independently (see below)
- **API keys** — `mcp_free_*` / `mcp_pro_*` / `mcp_test_*` prefixes auto-select plan and Stripe mode
- **Free tier** — 100 proofs/month, no credit card required
- **Agent identity** — optional `X-Agent-Identity` / `X-Agent-Version` headers, mismatch detection across calls
- **Triptyque de la Preuve** — 3-level watermarking on every transaction (see below)
- **Rate limiting** — daily cap (all keys) + monthly cap (free keys)
- **Email** — welcome + proof receipts via SMTP
- **Proof Specification** — open spec with test vectors for independent verification ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec))

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
# Edit .env with your Stripe keys, SMTP config…

# Run
uvicorn trust_layer.app:app --host 0.0.0.0 --port 8100

# Test
pytest tests/ -v
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/pricing` | Pricing and limits |
| `POST` | `/v1/proxy` | Proxied API call (charge + forward + proof) |
| `POST` | `/v1/keys/setup` | Buy initial credits + save card via Stripe Checkout (min 10 EUR) |
| `POST` | `/v1/keys/portal` | Open Stripe Billing Portal (update card, view invoices) |
| `POST` | `/v1/webhooks/stripe` | Stripe webhook receiver |
| `GET` | `/v1/usage` | Usage stats for a key |
| `GET` | `/v1/proof/{proof_id}` | Retrieve and verify proof (JSON or HTML — see content negotiation) |
| `GET` | `/v/{proof_id}` | Short URL — 302 redirect to `/v1/proof/{proof_id}` |
| `GET` | `/v1/proof/{proof_id}/tsr` | Download RFC 3161 timestamp response file |
| `POST` | `/v1/credits/buy` | Buy prepaid credits via Stripe Checkout (returns checkout URL) |
| `GET` | `/v1/pubkey` | ArkForge's Ed25519 public key for signature verification |
| `GET` | `/v1/agent/{agent_id}/reputation` | Public reputation score (0-100) for an agent |
| `POST` | `/v1/disputes` | File a dispute against a proof (authenticated) |
| `GET` | `/v1/agent/{agent_id}/disputes` | Public dispute history for an agent |

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
- **Green** (`#22c55e`) — integrity verified, certified timestamp via FreeTSA
- **Orange** (`#f59e0b`) — integrity verified, timestamp pending
- **Red** (`#ef4444`) — integrity check failed

The proof page shows 2 independent witnesses:
- **Ed25519 Signature** — proves ArkForge origin (green if signed, grey if not)
- **RFC 3161 Timestamp** — certified by FreeTSA.org (green when verified, orange when pending)

All proofs (Free and Pro) have 2 witnesses. Pro proofs additionally record the Stripe credit purchase receipt for audit.

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
PAYMENT_ID=$(echo -n "$PROOF" | jq -r '.certification_fee.transaction_id')
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

Every agent gets a deterministic reputation score (0-100) based on their proof history. No ML, no reviews — only factual data from proofs.

### Five dimensions

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Volume | 0.25 | Total number of proofs (cap: 100) |
| Regularity | 0.20 | Active days in last 30 days (cap: 20) |
| Seniority | 0.20 | Days since first proof (cap: 30) |
| Diversity | 0.15 | Unique services used (cap: 10) |
| Success | 0.20 | Proof success rate |

### Penalties

- **Identity mismatch** — 15% reduction if the agent changed its declared identity
- **Lost disputes** — 5% per lost dispute (floor: 50% of computed score)

### Get an agent's reputation

```bash
curl https://arkforge.fr/trust/v1/agent/{agent_id}/reputation
# → {"reputation_score": 63, "scores": {...}, "signature": "ed25519:...", ...}
```

The score is signed with ArkForge's Ed25519 key — verifiable via `/v1/pubkey`. Cached for 1 hour, recomputed lazily.

## Dispute System

Agents can contest proofs. Disputes are resolved instantly and automatically — no human intervention.

### How it works

1. An agent files a dispute: `POST /v1/disputes` with `proof_id` and `reason`
2. ArkForge re-checks the recorded upstream status code
3. Result: **UPHELD** (proof corrected), **DENIED** (contestant penalized), or **REJECTED** (not a party)

### Anti-abuse

- Losing a dispute costs -5% reputation score
- 1-hour cooldown between disputes
- Max 5 open disputes per agent
- 7-day dispute window after proof creation

### File a dispute

```bash
curl -X POST https://arkforge.fr/trust/v1/disputes \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{"proof_id": "prf_...", "reason": "Service returned 500 but proof says succeeded"}'
# → {"dispute_id": "disp_...", "status": "UPHELD", ...}
```

### View dispute history

```bash
curl https://arkforge.fr/trust/v1/agent/{agent_id}/disputes
# → {"disputes_filed": 5, "disputes_won": 3, "disputes_lost": 2, "recent_disputes": [...]}
```

## Architecture

```
Agent Client
    |
    v
Trust Layer (/v1/proxy)
    |--- 1. Validate API key + rate limit
    |--- 2. Deduct 1 credit (Pro/Test) or check monthly quota (Free)
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

## New client onboarding

### 1. Buy initial credits and get an API key

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "client@example.com", "amount": 10}'
# Returns: {"checkout_url": "https://checkout.stripe.com/...", "proofs_included": 100, ...}
```

Open `checkout_url` in a browser — enter a card. The first purchase (minimum 10 EUR = 100 proofs) is charged immediately and the card is saved for future off-session charges. Stripe webhook fires automatically: Trust Layer creates an API key (`mcp_pro_...`), credits the account, and emails the key to the client.

Free keys (`mcp_free_...`) are created without payment via `/v1/keys/free-signup`.

For test mode, add `"mode": "test"` and use Stripe test card `4242 4242 4242 4242`.

### 2. Buy more credits (off-session, no browser required)

```bash
curl -X POST https://arkforge.fr/trust/v1/credits/buy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 10.00}'
# Returns: {"credits_added": 10.0, "balance": 12.5, "proofs_available": 125, ...}
```

The saved card is charged directly — no browser redirect. Credits are added immediately.

### 2b. Manage card / view invoices

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/portal \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{}'
# Returns: {"portal_url": "https://billing.stripe.com/...", ...}
```

Open `portal_url` to update your payment method, download invoices, or cancel.

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

Each call deducts 1 credit. If the balance is 0, the call returns `402 Payment Required`.

## Credits

Pro and Test keys use prepaid credits. Each proof costs **0.10 EUR** (1 credit). Credits are bought in advance via Stripe Checkout and deducted automatically on each `/v1/proxy` call.

### Buy credits

```bash
curl -X POST https://arkforge.fr/trust/v1/credits/buy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 10.00}'
# Returns: {"credits_added": 10.0, "balance": 10.0, "proofs_available": 100, ...}
```

The saved card is charged off-session — no browser required. Credits are added immediately. Minimum purchase: 1.00 EUR (10 credits).

### Check balance

```bash
curl https://arkforge.fr/trust/v1/usage \
  -H "X-Api-Key: mcp_pro_..."
# Returns: {..., "credit_balance": 47, ...}
```

### How credits work

1. **Setup** — `POST /v1/keys/setup` (10 EUR minimum): Stripe Checkout charges the card, saves it for future use, and credits the account.
2. **Top up** — `POST /v1/credits/buy`: off-session charge, no browser required. Credits never expire.
3. **Use** — each `POST /v1/proxy` call deducts 1 credit (0.10 EUR). If balance is 0, the call is rejected with `402 Payment Required`.
4. **Alerts** — three email notifications keep you informed:
   - **80% quota** — when 80% of the daily/monthly quota is consumed
   - **Low balance** — when balance drops below 1.00 EUR (~10 proofs remaining), once per 24h
   - **Exhausted** — when a call is rejected due to zero balance (`402`), once per 24h — includes the recharge curl command

Free keys (`mcp_free_*`) do not use credits — they have a monthly quota of 100 proofs at no cost.

## Plans and API key prefixes

| Prefix | Plan | Payment | Witnesses | Limits |
|--------|------|---------|-----------|--------|
| `mcp_free_*` | Free | No charge | 2 (Ed25519, RFC 3161 TSA) | 100 proofs/month |
| `mcp_pro_*` | Pro | Prepaid credits (0.10 EUR/proof) | 2 (Ed25519, RFC 3161 TSA) | 100 proofs/day |
| `mcp_test_*` | Test | Test credits (Stripe test mode) | 2 (Ed25519, RFC 3161 TSA) | 100 proofs/day |

The proxy auto-selects the right plan, witnesses, and rate limits based on the API key prefix. Free tier skips Stripe entirely (no credit card required). Pro keys require a positive credit balance — buy credits via `POST /v1/credits/buy`. Test mode uses Stripe test keys (card `4242 4242 4242 4242`).

## Conformance testing

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

See a live proof: [example transaction](https://arkforge.fr/trust/v/prf_20260225_222329_d17acd)

Currently running with ArkForge-operated services. Third-party provider onboarding coming soon — see **[ROADMAP.md](ROADMAP.md)** for the multi-witness certification architecture.

Building a service you want to make verifiable? [Get in touch](mailto:contact@arkforge.fr).

## Live deployment

Running at **https://arkforge.fr/trust/v1/health**

## License

MIT — see [LICENSE](LICENSE).
