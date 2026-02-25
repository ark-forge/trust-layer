# ArkForge Trust Layer

Certifying proxy for agent-to-agent payments. Every API call that flows through the Trust Layer is metered, billed via Stripe, and gets a tamper-proof cryptographic proof (SHA-256 chain + optional OpenTimestamps).

## Features

- **Proxy** — forwards requests to upstream APIs, meters usage, creates proof
- **Payments** — Stripe off-session charges, test/live modes, webhook lifecycle
- **Proofs** — SHA-256 hash chain per call, publicly verifiable, optionally anchored on Bitcoin via OpenTimestamps
- **API keys** — `mcp_test_*` / `mcp_pro_*` prefixes auto-select Stripe mode
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
| `GET` | `/v1/proof/{proof_id}` | Retrieve and verify proof |
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

Response includes:
- `proof.payment` — Stripe transaction ID, amount, receipt URL
- `proof.hashes` — SHA-256 of request, response, and chain
- `proof.verification_url` — public URL to verify the proof
- `proof.opentimestamps` — OTS status and download URL
- `service_response` — upstream API response

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
    |--- 5. Submit to OpenTimestamps (async)
    |--- 6. Store proof, return everything
    |
    v
Upstream API (any HTTPS endpoint)
```

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
