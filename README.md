# ArkForge Trust Layer

**Cryptographic proof of what your agent executed.** Every API call through ArkForge produces an immutable, signed, timestamped receipt — verifiable by anyone, forever.

Not a log. Not a trace. A proof.

```bash
# One curl. Instant. No card required.
curl -X POST https://trust.arkforge.tech/v1/keys/free-signup \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
# → {"api_key": "mcp_free_xxxx...", "plan": "free", "limit": "500 proofs/month"}
```

[![Live](https://img.shields.io/badge/live-arkforge.tech-green)](https://trust.arkforge.tech/v1/health)
[![Spec](https://img.shields.io/badge/proof--spec-open-blue)](https://github.com/ark-forge/proof-spec)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

---

## Why ArkForge

When an agent calls an API, pays a provider, or executes a task on your behalf — what proof do you have?

Internal logs are mutable. Your agent can rewrite them. Your provider can deny delivery. In regulated environments (AI Act, DORA, NIS2), "the system said so" is not evidence.

ArkForge certifies the exact request sent, the exact response received, the payment made, and the exact moment it happened — bound in a cryptographic chain hash, signed with Ed25519, timestamped via RFC 3161, and anchored in Sigstore Rekor. **No field can be altered after the fact without breaking the proof.**

### Why not just use CloudTrail / a SIEM?

Cloud audit logs (CloudTrail, Azure Monitor, etc.) are controlled by the same party that generated the event. They prove nothing to a third party. A SIEM aggregates your own logs — it doesn't produce independent evidence.

ArkForge is a **neutral proxy**: it sits between your agent and any upstream API, records the exchange from the outside, signs it with its own key, and registers it in a public append-only log. Neither party controls the proof.

---

## How it works

```
Agent  →  POST /v1/proxy  →  ArkForge  →  Upstream API
                                ↓
                     SHA-256 chain hash
                     Ed25519 signature
                     RFC 3161 timestamp
                     Sigstore Rekor anchor
                                ↓
                     Immutable proof JSON + public HTML page
```

**One call, three independent witnesses:**

| Witness | What it proves | Verifiable by |
|---------|---------------|---------------|
| Ed25519 Signature | Proof was issued by ArkForge | Anyone with the public key |
| RFC 3161 Timestamp | Proof existed at the claimed time | Any RFC 3161 verifier |
| Sigstore Rekor | Chain hash in a public append-only log | [search.sigstore.dev](https://search.sigstore.dev) |

See a live proof: [example transaction](https://trust.arkforge.tech/v1/proof/prf_20260303_161853_4d0904)

---

## Get started in 60 seconds

### Step 1 — Free API key (no card)

```bash
curl -X POST https://trust.arkforge.tech/v1/keys/free-signup \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
# → {"api_key": "mcp_free_xxxx...", "plan": "free", "limit": "500 proofs/month"}
```

### Step 2 — Make a certified API call

```bash
curl -X POST https://trust.arkforge.tech/v1/proxy \
  -H "X-Api-Key: mcp_free_xxxx..." \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com/v1/run",
    "payload": {"task": "analyze", "text": "hello"}
  }'
```

ArkForge forwards your request, fingerprints the exchange (SHA-256), signs it (Ed25519), and returns the result with a proof.

### Step 3 — Verify

```bash
curl https://trust.arkforge.tech/v1/proof/prf_20260227_110211_a27069
```

Or open it in a browser — every proof has a public HTML verification page with a color-coded badge.

---

## Use cases

### Agent paying a provider

An autonomous agent calls a third-party API and pays for the service. ArkForge certifies the transaction: the exact request, the exact response, the payment evidence, and the timestamp — all bound in one cryptographic proof. The provider cannot deny delivery. The agent cannot deny the request.

```
Agent → POST /v1/proxy (with payment receipt URL) → ArkForge → Provider API
                                                          ↓
                                             Proof: request + response + receipt hash + timestamp
```

### MCP tool call certification

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) is becoming the standard for connecting AI agents to tools and external services. Every `tools/call` is a real-world action — but MCP has no built-in auditability. ArkForge fills that gap.

Route your MCP server's outbound calls through the Trust Layer proxy. Each tool call produces a signed, timestamped receipt — an **Agent Action Receipt (AAR)** — independently verifiable by your client, your auditor, or a regulator.

```
Claude / agent
     │ tools/call
     ▼
MCP Server  →  POST /v1/proxy  →  ArkForge  →  External API / service
                                      ↓
                         AAR: tool_name + args + result
                              + Ed25519 signature
                              + RFC 3161 timestamp
                              + Sigstore Rekor anchor
```

**What this gives you:**
- Proof that tool X was called with args Y and returned Z — not just a log entry
- Non-repudiation: the MCP server cannot later deny a call, the downstream service cannot deny delivery
- Portable receipts your client can verify without trusting your infrastructure

**One env var, zero SDK change:**

```bash
# Before: MCP server calls external APIs directly
EXTERNAL_API_URL=https://api.example.com

# After: route through Trust Layer
EXTERNAL_API_URL=https://trust.arkforge.tech/v1/proxy
ARKFORGE_API_KEY=mcp_pro_xxx...
ARKFORGE_TARGET=https://api.example.com
```

**Directly relevant to:** OWASP Top 10 for Agentic Applications 2026 (signed audit logs per tool call), EU AI Act Article 12 (logging for high-risk AI), DORA Article 11.

### Human auditing an agent

A team deploys an agent in production. The agent routes its LLM and API calls through ArkForge. The team gets a verifiable audit trail: which model, which exact prompt, what response, at what time, at what cost. Unlike internal logs, these proofs are signed and anchored — they cannot be altered after the fact.

```
Human client hires agent → agent routes all calls through ArkForge
                                         ↓
                            Immutable audit trail: model + prompt + response + timestamp + cost
                                         ↓
                            Human verifies: "here is exactly what my agent did"
```

**Directly relevant to:** DORA (Article 11 — ICT incident management), NIS2 (Article 21 — traceability), EU AI Act (Article 12 — logging obligations for high-risk AI systems).

---

## Features

### Core
- **Execution certification** — every API call produces a cryptographic proof of what was sent, received, and when. Immutable after creation.
- **Chain hash** — SHA-256 binding of request, response, payment, timestamp, buyer, and seller. Public formula, independently recomputable.
- **Ed25519 signature** — every proof signed by ArkForge's private key. Public key at `GET /v1/pubkey`.
- **RFC 3161 timestamps** — certified via a pool of trusted timestamp authorities. First success wins; provider recorded per proof.
- **Sigstore Rekor** — chain hash registered in the Linux Foundation's append-only public transparency log.
- **Open proof spec** — deterministic format with test vectors. Any third party can verify a proof without ArkForge's code. [ark-forge/proof-spec](https://github.com/ark-forge/proof-spec)

### Payment evidence (Mode B)
- Attach a Stripe receipt URL to any proxy call. ArkForge fetches it directly from Stripe, hashes the raw content (SHA-256), and binds it to the proof. The receipt hash is what counts — it holds even if field parsing fails.
- **ArkForge does not intermediate this payment.** The proof records what it observed at the PSP.

### Agent identity
- Optional `X-Agent-Identity` / `X-Agent-Version` headers stored in every proof.
- Identity mismatch across calls is flagged: `identity_consistent: false`.
- Reputation score (0–100) computed deterministically from proof history. No ML, no reviews. [Formula](#reputation-score).

### Triptyque de la Preuve
Every transaction carries the ArkForge mark at three levels:

| Level | Where | For whom |
|-------|-------|----------|
| **Digital Stamp** | `_arkforge_attestation` in JSON body | Machines / agent-to-agent |
| **Ghost Stamp** | `X-ArkForge-*` response headers | API gateways, middleware, monitoring |
| **Visual Stamp** | Public HTML proof page with color badge | Humans, auditors, regulators |

---

## Plans

| Plan | Price | Monthly quota | Overage (opt-in) |
|------|-------|--------------|-----------------|
| **Free** | Free | 500 proofs | Not available |
| **Pro** | €29/month | 5,000 proofs | €0.01/proof (cap €5–€100) |
| **Enterprise** | €149/month | 50,000 proofs | €0.005/proof (cap €5–€100) |

API key prefix auto-selects plan, rate limits, and billing mode (`mcp_free_*` / `mcp_pro_*` / `mcp_ent_*`). Overage billing is **disabled by default** — opt in explicitly at `POST /v1/keys/overage`.

For enterprise requirements (eIDAS-qualified timestamps, on-premise deployment, volume above 50k/month): [contact@arkforge.fr](mailto:contact@arkforge.fr)

---

## API reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/pricing` | Plans and limits |
| `POST` | `/v1/proxy` | Certified proxy call |
| `POST` | `/v1/keys/free-signup` | Create free API key |
| `POST` | `/v1/keys/setup` | Subscribe to Pro or Enterprise (Stripe Checkout) |
| `POST` | `/v1/keys/portal` | Open Stripe Billing Portal |
| `POST` | `/v1/keys/overage` | Enable/disable overage billing |
| `GET` | `/v1/usage` | Usage stats and credit balance |
| `GET` | `/v1/proof/{proof_id}` | Retrieve proof (JSON or HTML) |
| `GET` | `/v/{proof_id}` | Short URL — redirect to proof |
| `GET` | `/v1/proof/{proof_id}/tsr` | Download RFC 3161 timestamp file |
| `POST` | `/v1/credits/buy` | Buy prepaid overage credits |
| `GET` | `/v1/pubkey` | ArkForge's Ed25519 public key |
| `GET` | `/v1/agent/{agent_id}/reputation` | Agent reputation score (0–100) |

### POST /v1/proxy — request body

```json
{
  "target": "https://api.example.com/endpoint",
  "method": "POST",
  "payload": {"task": "analyze"},
  "description": "optional label for the proof",

  // Optional: attach external payment evidence (Mode B)
  "provider_payment": {
    "type": "stripe",
    "receipt_url": "https://pay.stripe.com/receipts/payment/CAcaFwo..."
  },

  // Optional: forward headers to the target API
  "extra_headers": {
    "Authorization": "Bearer token",
    "Accept": "application/json"
  }
}
```

**Optional request headers:**

| Header | Description |
|--------|-------------|
| `X-Agent-Identity` | Agent's self-declared name |
| `X-Agent-Version` | Agent's version string |

### Proxy limits

| Limit | Value |
|-------|-------|
| Target protocol | HTTPS only |
| Payload format | JSON only |
| Response timeout | 120 seconds |
| Response hashed | 1 MB max (truncated) |
| `extra_headers` | Max 10, max 4096 chars per value |
| Monthly quota | 500 / 5,000 / 50,000 (Free / Pro / Enterprise) |

---

## Chain hash algorithm

The chain hash formula is public and deterministic. Anyone can recompute it:

```
chain_hash = SHA256(
  request_hash + response_hash + transaction_id + timestamp +
  buyer_fingerprint + seller
  [+ upstream_timestamp]         // if present in proof
  [+ receipt_content_hash]       // if provider_payment present
)
```

All values concatenated as raw UTF-8 strings, no separator. Canonical JSON: `json.dumps(data, sort_keys=True, separators=(",", ":"))`.

### Verify any proof in one command

```bash
PROOF=$(curl -s https://trust.arkforge.tech/v1/proof/prf_...)

REQUEST_HASH=$(echo "$PROOF" | jq -r '.hashes.request' | sed 's/sha256://')
RESPONSE_HASH=$(echo "$PROOF" | jq -r '.hashes.response' | sed 's/sha256://')
PAYMENT_ID=$(echo "$PROOF" | jq -r '.certification_fee.transaction_id')
TIMESTAMP=$(echo "$PROOF" | jq -r '.timestamp')
BUYER=$(echo "$PROOF" | jq -r '.parties.buyer_fingerprint')
SELLER=$(echo "$PROOF" | jq -r '.parties.seller')
UPSTREAM=$(echo "$PROOF" | jq -r '.upstream_timestamp // empty')
RECEIPT=$(echo "$PROOF" | jq -r '.provider_payment.receipt_content_hash // empty' | sed 's/sha256://')

COMPUTED=$(printf '%s' "${REQUEST_HASH}${RESPONSE_HASH}${PAYMENT_ID}${TIMESTAMP}${BUYER}${SELLER}${UPSTREAM}${RECEIPT}" \
  | sha256sum | cut -d' ' -f1)

EXPECTED=$(echo "$PROOF" | jq -r '.hashes.chain' | sed 's/sha256://')
[ "$COMPUTED" = "$EXPECTED" ] && echo "VERIFIED" || echo "TAMPERED"
```

**Current ArkForge public key:**
```
ed25519:ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY
```

---

## Reputation Score

Every agent gets a deterministic reputation score (0–100) based on proof history alone. No ML, no manual reviews.

```
score = floor(success_rate × confidence) − penalties
```

| Volume | Confidence |
|--------|-----------|
| 0–1 proofs | 0.60 (provisional) |
| 2–4 proofs | 0.75 |
| 5–19 proofs | 0.85 |
| 20+ proofs | 1.00 |

**Penalty:** −15 if the agent changed its declared `X-Agent-Identity` across calls.

The score is signed with ArkForge's Ed25519 key. Cached 1 hour, recomputed lazily.

```bash
curl https://trust.arkforge.tech/v1/agent/{agent_id}/reputation
```

---

## Self-hosting

> Self-hosted instances provide cryptographic integrity but carry no independent third-party attestation. For proofs verifiable by external parties, use the hosted service at [arkforge.tech/trust](https://arkforge.tech/trust).

```bash
git clone https://github.com/ark-forge/trust-layer.git
cd trust-layer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"

cp .env.example .env
# Configure STRIPE_LIVE_SECRET_KEY, RESEND API key, etc.

uvicorn trust_layer.app:app --host 127.0.0.1 --port 8100
pytest tests/ -v
```

### Key environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TRUST_LAYER_BASE_URL` | Yes | Public base URL (e.g. `https://trust.arkforge.tech`) |
| `STRIPE_LIVE_SECRET_KEY` | Yes | Stripe live secret key |
| `STRIPE_TL_WEBHOOK_SECRET` | Yes | Stripe webhook signing secret |
| `REDIS_URL` | No | Redis for atomic rate limiting (falls back to file lock if absent) |
| `KEYS_FERNET_KEY` | No | AES-128 key for `api_keys.json` encryption at rest |
| `TSA_PRIMARY_URL` | No | Override primary TSA endpoint (e.g. inject a QTSP endpoint for eIDAS compliance) |

Full variable reference: see `.env.example`.

### Production setup

**nginx:**
```nginx
location /trust/ {
    proxy_pass http://127.0.0.1:8100/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

**systemd:**
```ini
[Service]
User=arkforge
WorkingDirectory=/opt/trust-layer
EnvironmentFile=/opt/trust-layer/.env
ExecStart=/opt/trust-layer/.venv/bin/uvicorn trust_layer.app:app \
  --host 127.0.0.1 --port 8100 --workers 4
Restart=always
```

> Uvicorn **must** bind to `127.0.0.1`, not `0.0.0.0`. Verify: `ss -tlnp | grep 8100`

### Signing key

Auto-generated at `.signing_key.pem` on first run. **Back it up — losing it means existing proofs cannot be signature-verified.**

```bash
chmod 600 .signing_key.pem .env
```

---

## Security

- **SSRF protection** — private IP ranges, loopback, link-local, cloud IMDS (`169.254.x.x`) all blocked before DNS resolution. DNS rebinding guard re-checks resolved addresses.
- **Receipt fetching** — only whitelisted PSP domains (Stripe), HTTPS only, 500 KB max, 10s timeout.
- **Encryption at rest** — `api_keys.json` encrypted with AES-128 (Fernet). Proof files contain only SHA-256 hashes, never payload content.
- **Security smoke test** — 55 checks covering auth bypass, SSRF vectors, path traversal, webhook replay, input validation: `python3 scripts/security_smoke_test.py --url https://trust.arkforge.tech --key mcp_free_xxx`
- **CVE scanning** — `pip-audit` after any dependency update.

---

## Error codes

| Code | HTTP | Description |
|------|------|-------------|
| `invalid_api_key` | 401 | Missing, invalid, or inactive API key |
| `invalid_target` | 400 | Target is not HTTPS, or resolves to a private range |
| `invalid_request` | 400 | Missing field, invalid JSON, or malformed input |
| `invalid_plan` | 403 | Operation not available on this plan |
| `rate_limited` | 429 | Monthly quota exceeded (enable overage or wait for next month) |
| `overage_cap_reached` | 429 | Monthly overage cap reached |
| `insufficient_credits` | 402 | Credit balance too low — recharge at `/v1/credits/buy` |
| `proxy_timeout` | 504 | Upstream timed out (proof still issued) |
| `service_error` | 502 | Upstream returned an error (proof still issued) |
| `not_found` | 404 | Proof or resource not found |
| `internal_error` | 500 | Internal server error |

---

## Ecosystem

| Component | Description | Repo |
|-----------|-------------|------|
| **Trust Layer** | This repo — certifying proxy, billing, proof chain | [ark-forge/trust-layer](https://github.com/ark-forge/trust-layer) |
| **Proof Spec** | Open specification + test vectors | [ark-forge/proof-spec](https://github.com/ark-forge/proof-spec) |
| **MCP EU AI Act** | Compliance scanner — first service sold through ArkForge | [ark-forge/mcp-eu-ai-act](https://github.com/ark-forge/mcp-eu-ai-act) |
| **Agent Client** | Autonomous buyer — proof-of-concept non-human customer | [ark-forge/arkforge-agent-client](https://github.com/ark-forge/arkforge-agent-client) |

---

## Roadmap

See **[ROADMAP.md](ROADMAP.md)** — current focus: third-party provider onboarding (Phase 2), multi-PSP payment orchestration (Phase 3).

---

## Live deployment

[https://trust.arkforge.tech/v1/health](https://trust.arkforge.tech/v1/health)

## License

MIT — see [LICENSE](LICENSE).
