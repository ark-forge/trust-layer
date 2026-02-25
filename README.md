# ArkForge Trust Layer

Add verifiable execution to any API call.

ArkForge is a certifying proxy that forwards requests to any HTTPS API, charges programmatically via Stripe, and returns a tamper-proof cryptographic proof (SHA-256 hash chain + optional Bitcoin timestamp).

Every call becomes: **metered** → **paid** → **provable**.

## One-line example

```
Without ArkForge:   Agent → API → Result
With ArkForge:      Agent → ArkForge → API → Verifiable Proof
```

## Why use it?

- Prove what your agent actually did
- Attach payments to execution
- Create audit-ready API calls
- Add trust without modifying existing services

## Features

- **Proxy** — forwards requests to upstream APIs, meters usage, creates proof
- **Payments** — Stripe off-session charges, test/live modes, webhook lifecycle
- **Proofs** — SHA-256 hash chain per call, publicly verifiable, optionally anchored on Bitcoin via OpenTimestamps and archived on Archive.org
- **API keys** — `mcp_test_*` / `mcp_pro_*` prefixes auto-select Stripe mode
- **Agent identity** — optional `X-Agent-Identity` / `X-Agent-Version` headers, mismatch detection across calls
- **Triptyque de la Preuve** — 3-level watermarking on every transaction (see below)
- **Rate limiting** — per-key daily limits
- **Email** — welcome + proof receipts via SMTP

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
| `GET` | `/v1/proof/{proof_id}/ots` | Download OpenTimestamps file |

## Core flow — POST /v1/proxy

```json
{
  "target": "https://example.com/api/scan",
  "amount": 0.50,
  "currency": "eur",
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
- `proof.payment` — Stripe transaction ID, amount, receipt URL
- `proof.hashes` — SHA-256 of request, response, and chain
- `proof.parties.agent_identity` / `agent_version` — declared identity (if provided)
- `proof.identity_consistent` — `true` / `false` / `null` (consistency check)
- `proof.verification_url` — public URL to verify the proof
- `proof.opentimestamps` — OTS status and download URL
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
- **Green** (`#22c55e`) — integrity verified, OTS confirmed on Bitcoin
- **Orange** (`#f59e0b`) — integrity verified, OTS pending
- **Red** (`#ef4444`) — integrity check failed

The proof page shows 3 independent witnesses:
- **Stripe** — confirms payment occurred (green if receipt URL exists)
- **Bitcoin** — confirms timestamp via OpenTimestamps (green when confirmed, orange when pending)
- **Archive.org** — public snapshot of the proof page on the Wayback Machine (green if snapshot exists, grey if not yet available)

**Short URL:** `GET /v/{proof_id}` → 302 redirect to the full proof endpoint. Cacheable (24h).

## Chain hash algorithm

The chain hash binds every element of a transaction into a single verifiable seal. The formula is public and deterministic — anyone can recompute it:

```
chain_hash = SHA256(request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller)
```

Where:
- `request_hash` = SHA-256 of the canonical JSON request (sorted keys, no whitespace)
- `response_hash` = SHA-256 of the canonical JSON response
- `payment_intent_id` = Stripe Payment Intent ID (e.g. `pi_3T4ovu...`)
- `timestamp` = ISO 8601 UTC (e.g. `2026-02-25T20:43:45Z`)
- `buyer_fingerprint` = SHA-256 of the API key
- `seller` = target domain (e.g. `example.com`)

All values are concatenated as raw strings (no separator) before hashing. Canonical JSON uses `json.dumps(data, sort_keys=True, separators=(",", ":"))`.

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

# 2. Recompute the chain hash
COMPUTED=$(echo -n "${REQUEST_HASH}${RESPONSE_HASH}${PAYMENT_ID}${TIMESTAMP}${BUYER}${SELLER}" | sha256sum | cut -d' ' -f1)

# 3. Compare with the proof's chain hash
EXPECTED=$(echo -n "$PROOF" | jq -r '.hashes.chain' | sed 's/sha256://')
[ "$COMPUTED" = "$EXPECTED" ] && echo "VERIFIED" || echo "TAMPERED"
```

If the chain hash matches, no field in the proof was altered after creation. The Stripe Payment Intent ID can be independently verified on Stripe's dashboard or API.

## Architecture

```
Agent Client
    |
    v
Trust Layer (/v1/proxy)
    |--- 1. Validate API key + rate limit
    |--- 2. Charge via Stripe (off-session)
    |--- 3. Forward request to upstream API
    |--- 4. Hash request + response (SHA-256 chain)
    |--- 5. Store proof, return response immediately
    |--- 6. Background: OpenTimestamps + Archive.org snapshot + email receipt
    |
    v
Upstream API (any HTTPS endpoint)
```

**No database.** Proofs are stored as immutable JSON files on disk — one file per transaction (`proofs/{proof_id}.json`). No SQL, no edits, no deletions. Once written, a proof can only be read. This guarantees that proofs cannot be retroactively altered.

## New client onboarding

### 1. Save a card

```bash
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "client@example.com"}'
# Returns: {"checkout_url": "https://checkout.stripe.com/...", ...}
```

Open `checkout_url` in a browser — enter a card. No charge yet.

For test mode, add `"mode": "test"` and use Stripe test card `4242 4242 4242 4242`.

### 2. Receive API key

Stripe webhook fires automatically. The Trust Layer creates an API key (`mcp_pro_...` or `mcp_test_...`) and emails it to the client.

### 3. Use the proxy

```bash
curl -X POST https://arkforge.fr/trust/v1/proxy \
  -H "X-Api-Key: mcp_pro_..." \
  -H "X-Agent-Identity: my-agent" \
  -H "X-Agent-Version: 1.0.0" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://arkforge.fr/api/v1/scan-repo",
    "amount": 0.50,
    "currency": "eur",
    "payload": {"repo_url": "https://github.com/owner/repo"}
  }'
```

## Test / Live modes

API keys starting with `mcp_test_` use Stripe test mode. Keys starting with `mcp_pro_` use Stripe live mode. The proxy auto-selects the right Stripe keys based on the API key prefix. Both modes work simultaneously — same endpoints, same proofs.

## Live deployment

Running at **https://arkforge.fr/trust/v1/health**

## License

MIT — see [LICENSE](LICENSE).
