# ArkForge Trust Layer

Certifying proxy for agent-to-agent payments. Every API call that flows through the Trust Layer is metered, billed via Stripe, and gets a tamper-proof cryptographic proof (SHA-256 chain + optional OpenTimestamps).

## Features

- **Proxy** — forwards requests to upstream APIs (Claude, GPT, MCP servers…), meters token usage
- **Payments** — Stripe Checkout sessions, usage-based billing, webhook lifecycle
- **Proofs** — SHA-256 hash chain per call, verifiable, optionally anchored on Bitcoin via OpenTimestamps
- **API keys** — test/live modes, rate limiting, key rotation
- **Email** — welcome + proof receipts via SMTP

## Quick start

```bash
# Clone & install
git clone https://github.com/ArkForge/trust-layer.git
cd trust-layer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

# Configure
cp .env.example .env
# Edit .env with your Stripe keys, SMTP, upstream URL…

# Run
uvicorn trust_layer.app:app --host 0.0.0.0 --port 8100

# Test
pytest tests/ -v
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/v1/proxy` | Proxied API call (metered + proof) |
| `POST` | `/v1/keys` | Create API key |
| `DELETE` | `/v1/keys/{ref}` | Deactivate key |
| `GET` | `/v1/usage` | Usage stats for a key |
| `POST` | `/v1/checkout` | Create Stripe Checkout session |
| `POST` | `/v1/webhook/stripe` | Stripe webhook receiver |
| `GET` | `/v1/proofs/{proof_id}` | Retrieve proof |
| `GET` | `/v1/proofs/{proof_id}/verify` | Verify proof integrity |

## Architecture

```
Client → Trust Layer (proxy + meter + proof) → Upstream API
                ↓
         Stripe (billing)
                ↓
         Proof store (JSON + SHA-256 chain)
```

## Test / Live modes

API keys starting with `tk_test_` use Stripe test mode. Keys starting with `tk_live_` use Stripe live mode. The proxy auto-selects the right Stripe keys based on the API key prefix.

## License

MIT — see [LICENSE](LICENSE).
