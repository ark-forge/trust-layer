# ArkForge Trust Layer

Add verifiable execution to any API call.

ArkForge is a certifying proxy that forwards requests to any HTTPS API and returns a tamper-proof cryptographic proof (SHA-256 hash chain + Ed25519 signature + RFC 3161 certified timestamp). The Pro plan uses prepaid credits (0.10 EUR/proof) and adds Stripe as a 3rd independent witness.

Every call becomes: **forwarded** → **proven** → **verifiable**.

## One-line example

```
Without ArkForge:   Agent → API → Result
With ArkForge:      Agent → ArkForge → API → Verifiable Proof
```

## Why use it?

- Prove what your agent actually did
- Attach prepaid credits to execution
- Create audit-ready API calls
- Add trust without modifying existing services

## Features

- **Proxy** — forwards requests to upstream APIs, meters usage, creates proof
- **Prepaid credits** — buy credits via Stripe Checkout, deducted per proof (0.10 EUR/proof)
- **Proofs** — SHA-256 hash chain per call, publicly verifiable, anchored via RFC 3161 Timestamp Authority and archived on Archive.org
- **Ed25519 signature** — every proof is signed by ArkForge's Ed25519 key, proving origin. Public key served at `GET /v1/pubkey`
- **API keys** — `mcp_free_*` / `mcp_pro_*` / `mcp_test_*` prefixes auto-select plan and Stripe mode
- **Free tier** — 100 proofs/month, no credit card required
- **Agent identity** — optional `X-Agent-Identity` / `X-Agent-Version` headers, mismatch detection across calls
- **Triptyque de la Preuve** — 3-level watermarking on every transaction (see below)
- **Rate limiting** — daily cap (all keys) + monthly cap (free keys)
- **Email** — welcome + proof receipts via SMTP
- **Proof Specification** — open spec with test vectors for independent verification ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec))

## Quick start

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
| `POST` | `/v1/keys/setup` | Save a card via Stripe Checkout |
| `POST` | `/v1/webhooks/stripe` | Stripe webhook receiver |
| `GET` | `/v1/usage` | Usage stats for a key |
| `GET` | `/v1/proof/{proof_id}` | Retrieve and verify proof (JSON or HTML — see content negotiation) |
| `GET` | `/v/{proof_id}` | Short URL — 302 redirect to `/v1/proof/{proof_id}` |
| `GET` | `/v1/proof/{proof_id}/tsr` | Download RFC 3161 timestamp response file |
| `POST` | `/v1/credits/buy` | Buy prepaid credits via Stripe Checkout (returns checkout URL) |
| `GET` | `/v1/pubkey` | ArkForge's Ed25519 public key for signature verification |

## Core flow — POST /v1/proxy

```json
{
  "target": "https://example.com/api/scan",
  "method": "POST",
  "payload": {"repo_url": "https://github.com/owner/repo"},
  "description": "EU AI Act compliance scan"
}
```

**Optional headers:**

| Header | Description |
|--------|-------------|
| `X-Agent-Identity` | Agent's self-declared name (e.g. `my-agent-v1`) |
| `X-Agent-Version` | Agent's version string (e.g. `2.0.3`) |

These are stored in the proof and shadow profile. If the same API key sends a different identity, all subsequent proofs are flagged `identity_consistent: false`.

**Response includes:**
- `proof.spec_version` — proof format version (see [proof-spec](https://github.com/ark-forge/proof-spec))
- `proof.payment` — Stripe transaction ID, credit deduction, receipt URL
- `proof.hashes` — SHA-256 of request, response, and chain
- `proof.arkforge_signature` — Ed25519 signature of the chain hash (format: `ed25519:<base64url>`)
- `proof.arkforge_pubkey` — ArkForge's Ed25519 public key used for signing
- `proof.upstream_timestamp` — upstream service's `Date` header (if present)
- `proof.parties.agent_identity` / `agent_version` — declared identity (if provided)
- `proof.identity_consistent` — `true` / `false` / `null` (consistency check)
- `proof.verification_url` — public URL to verify the proof
- `proof.timestamp_authority` — TSA status, provider, download URL, and `tsr_base64` (after background processing)
- `proof.archive_org` — Archive.org snapshot URL (if available)
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

The proof page shows up to 3 independent witnesses:
- **Ed25519 Signature** — proves ArkForge origin (green if signed, grey if not)
- **RFC 3161 Timestamp** — certified by FreeTSA.org (green when verified, orange when pending)
- **Archive.org** — public snapshot of the proof page on the Wayback Machine (green if snapshot exists, grey if not yet available)

All proofs (Free and Pro) have 3 witnesses. Pro proofs additionally record the Stripe credit purchase receipt for audit.

**Short URL:** `GET /v/{proof_id}` → 302 redirect to the full proof endpoint. Cacheable (24h).

## Chain hash algorithm

The chain hash binds every element of a transaction into a single verifiable seal. The formula is public and deterministic — anyone can recompute it:

```
chain_hash = SHA256(request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller [+ upstream_timestamp])
```

Where:
- `request_hash` = SHA-256 of the canonical JSON request (sorted keys, no whitespace)
- `response_hash` = SHA-256 of the canonical JSON response
- `payment_intent_id` = Stripe Payment Intent ID (e.g. `pi_3T4ovu...`) or `free_tier` for free plan proofs
- `timestamp` = ISO 8601 UTC (e.g. `2026-02-25T20:43:45Z`)
- `buyer_fingerprint` = SHA-256 of the API key
- `seller` = target domain (e.g. `example.com`)
- `upstream_timestamp` = upstream service's `Date` header (included **only** when present in the proof JSON)

All values are concatenated as raw strings (no separator) before hashing. Canonical JSON uses `json.dumps(data, sort_keys=True, separators=(",", ":"))`.

**Backward compatibility:** if `upstream_timestamp` is absent or null in the proof JSON, it is not included in the chain input. This preserves verification of proofs created before this field was introduced.

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

**What the signature guarantees:** integrity of all fields covered by the chain hash (request, response, payment, timestamp, buyer, seller, upstream_timestamp if present).

**What the signature does NOT cover:** `views_count`, `identity_consistent`, `archive_org`, and other informational/mutable metadata.

## Independent verification

You can verify any proof without ArkForge's code. Given a proof JSON:

```bash
# 1. Extract the components
REQUEST_HASH=$(echo -n "$PROOF" | jq -r '.hashes.request' | sed 's/sha256://')
RESPONSE_HASH=$(echo -n "$PROOF" | jq -r '.hashes.response' | sed 's/sha256://')
PAYMENT_ID=$(echo -n "$PROOF" | jq -r '.payment.transaction_id')
TIMESTAMP=$(echo -n "$PROOF" | jq -r '.timestamp')
BUYER=$(echo -n "$PROOF" | jq -r '.parties.buyer_fingerprint')
SELLER=$(echo -n "$PROOF" | jq -r '.parties.seller')
UPSTREAM=$(echo -n "$PROOF" | jq -r '.upstream_timestamp // empty')

# 2. Recompute the chain hash
COMPUTED=$(echo -n "${REQUEST_HASH}${RESPONSE_HASH}${PAYMENT_ID}${TIMESTAMP}${BUYER}${SELLER}${UPSTREAM}" | sha256sum | cut -d' ' -f1)

# 3. Compare with the proof's chain hash
EXPECTED=$(echo -n "$PROOF" | jq -r '.hashes.chain' | sed 's/sha256://')
[ "$COMPUTED" = "$EXPECTED" ] && echo "VERIFIED" || echo "TAMPERED"
```

If the chain hash matches, no field in the proof was altered after creation. For Pro proofs, the Stripe Payment Intent ID can be independently verified on Stripe's dashboard or API. For Free proofs, the payment_intent_id is `free_tier`.

To also verify the Ed25519 signature, use the public key from `GET /v1/pubkey` (or the value above) with any Ed25519 library. The signed message is the chain hash hex string.

## Architecture

```
Agent Client
    |
    v
Trust Layer (/v1/proxy)
    |--- 1. Validate API key + rate limit
    |--- 2. Deduct 1 credit (Pro/Test) or check monthly quota (Free)
    |--- 3. Forward request to upstream API
    |--- 4. Hash request + response (SHA-256 chain)
    |--- 5. Store proof, return response immediately
    |--- 6. Background: RFC 3161 timestamp + Archive.org snapshot + email receipt
    |
    v
Upstream API (any HTTPS endpoint)
```

**No database.** Proofs are stored as immutable JSON files on disk — one file per transaction (`proofs/{proof_id}.json`). No SQL, no edits, no deletions. Once written, a proof can only be read. This guarantees that proofs cannot be retroactively altered.

## New client onboarding

### 1. Save a card and get an API key

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "client@example.com"}'
# Returns: {"checkout_url": "https://checkout.stripe.com/...", ...}
```

Open `checkout_url` in a browser — enter a card. No charge yet. Stripe webhook fires automatically and the Trust Layer creates an API key (`mcp_pro_...`) and emails it to the client. Free keys (`mcp_free_...`) are created without payment.

For test mode, add `"mode": "test"` and use Stripe test card `4242 4242 4242 4242`.

### 2. Buy credits

```bash
curl -X POST https://arkforge.fr/trust/v1/credits/buy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 5.00}'
# Returns: {"checkout_url": "https://checkout.stripe.com/...", "credits": 50, ...}
```

Complete payment in browser. Credits (0.10 EUR each) are added to the key automatically.

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
  -d '{"amount": 5.00}'
# Returns: {"checkout_url": "https://checkout.stripe.com/...", "credits": 50, ...}
```

Open `checkout_url` in a browser to complete payment. Credits are added to the key once Stripe confirms the payment (via webhook). Minimum purchase: 1.00 EUR (10 credits).

### Check balance

```bash
curl https://arkforge.fr/trust/v1/usage \
  -H "X-Api-Key: mcp_pro_..."
# Returns: {..., "credit_balance": 47, ...}
```

### How credits work

1. **Buy** — `POST /v1/credits/buy` with desired EUR amount. Stripe Checkout session is created.
2. **Pay** — complete payment in browser. Webhook adds credits to the key.
3. **Use** — each `POST /v1/proxy` call deducts 1 credit (0.10 EUR). If balance is 0, the call is rejected with `402 Payment Required`.
4. **Top up** — buy more credits anytime. Credits never expire.

Free keys (`mcp_free_*`) do not use credits — they have a monthly quota of 100 proofs at no cost.

## Plans and API key prefixes

| Prefix | Plan | Payment | Witnesses | Limits |
|--------|------|---------|-----------|--------|
| `mcp_free_*` | Free | No charge | 3 (Ed25519, RFC 3161, Archive.org) | 100 proofs/month |
| `mcp_pro_*` | Pro | Prepaid credits (0.10 EUR/proof) | 3 (Ed25519, RFC 3161, Archive.org) | 100 proofs/day |
| `mcp_test_*` | Test | Test credits (Stripe test mode) | 3 (Ed25519, RFC 3161, Archive.org) | 100 proofs/day |

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

Currently running with ArkForge-operated services. Third-party provider onboarding coming soon — see **[ROADMAP.md](ROADMAP.md)** for the multi-witness notarization architecture.

Building a service you want to make verifiable? [Get in touch](mailto:contact@arkforge.fr).

## Live deployment

Running at **https://arkforge.fr/trust/v1/health**

## License

MIT — see [LICENSE](LICENSE).
