# Trust Layer — Quick Reference

## Two modes

```
┌──────────────────────────────────────────────────────┐
│ MODE A — Transaction proof only                      │
└──────────────────────────────────────────────────────┘

Agent → Provider (any payment, outside Trust Layer)
Agent → Trust Layer (certification)
        └─ Proof: request + response + timestamp
        └─ No payment proof

Use case: traceability, audit log, execution trace


┌──────────────────────────────────────────────────────┐
│ MODE B — Transaction + payment proof                 │
└──────────────────────────────────────────────────────┘

Agent → Provider (Stripe payment, receives receipt_url)
Agent → Trust Layer (certification + provider_payment)
        └─ Proof: request + response + timestamp + receipt
        └─ Payment proof included

Use case: financial audit, compliance, non-repudiation


┌──────────────────────────────────────────────────────┐
│ MODE C — Certified action on a third-party API       │
└──────────────────────────────────────────────────────┘

Agent → Trust Layer (certification + extra_headers)
        └─ Trust Layer forwards headers to target API
        └─ Proof: request (incl. auth) + response + timestamp
        └─ Token value hashed, not stored

Use case: certified GitHub comments, Slack messages,
          any API requiring its own auth token
```

---

## 3 steps

### 1 — Get a key

```bash
# Free (500/month, no card)
curl -X POST https://trust.arkforge.tech/v1/keys/free-signup \
  -d '{"email": "you@example.com"}'

# Pro Test (development)
curl -X POST https://trust.arkforge.tech/v1/keys/setup \
  -d '{"email": "you@example.com", "plan": "pro", "mode": "test"}'
# → Open checkout_url, card 4242 4242 4242 4242

# Pro production (€29/month)
curl -X POST https://trust.arkforge.tech/v1/keys/setup \
  -d '{"email": "you@example.com", "plan": "pro"}'
# → Open checkout_url, real card → mcp_pro_xxx by email

# Enterprise production (€149/month)
curl -X POST https://trust.arkforge.tech/v1/keys/setup \
  -d '{"email": "you@example.com", "plan": "enterprise"}'
# → Open checkout_url, real card → mcp_ent_xxx by email

# Platform production (€599/month — 500k proofs, DigiCert TSA)
curl -X POST https://trust.arkforge.tech/v1/keys/setup \
  -d '{"email": "you@example.com", "plan": "platform"}'
# → Open checkout_url, real card → mcp_plat_xxx by email
```

---

### 2 — Modify your code

#### Mode A (transaction only)

```python
# BEFORE
response = requests.post("https://provider.com/api", json={...})

# AFTER
response = requests.post(
    "https://trust.arkforge.tech/v1/proxy",
    headers={"X-Api-Key": "mcp_xxx..."},
    json={
        "target": "https://provider.com/api",
        "payload": {...}
    }
)
```

#### Mode C (certified action — extra_headers)

```python
response = requests.post(
    "https://trust.arkforge.tech/v1/proxy",
    headers={"X-Api-Key": "mcp_xxx..."},
    json={
        "target": "https://api.github.com/repos/owner/repo/issues/5/comments",
        "method": "POST",
        "payload": {"body": "Automated analysis complete."},
        "extra_headers": {
            "Authorization": "token ghp_xxx",
            "Accept": "application/vnd.github+json"
        }
    }
)
# Constraints: max 10 headers, values ≤ 4096 chars
# Blocked: Host, Transfer-Encoding, Connection, Upgrade,
#          Content-Length, Content-Type, X-Internal-Secret
```

#### Mode B (transaction + payment)

ArkForge does not handle money. The agent pays the provider **directly**
via Stripe, then attaches that receipt as proof.

```python
# 1. Agent pays provider directly via Stripe (your Stripe account)
payment = stripe.PaymentIntent.create(amount=500, ..., expand=["charges"])
receipt_url = payment.charges.data[0].receipt_url
# ↑ This is the receipt of payment TO the provider — NOT to ArkForge

# 2. Certification: attach payment evidence to proxy call
# Free key is sufficient for Mode B (no credit deduction)
response = requests.post(
    "https://trust.arkforge.tech/v1/proxy",
    headers={"X-Api-Key": "mcp_xxx..."},
    json={
        "target": "https://provider.com/api",
        "payload": {...},
        "provider_payment": {           # ← 3 extra lines
            "type": "stripe",
            "receipt_url": receipt_url  # ← direct provider payment receipt
        }
    }
)
```

---

### 3 — Retrieve the proof

```python
result = response.json()

# Upstream result
data = result['service_response']['body']

# Proof
proof_id = result['proof']['id']
proof_url = result['proof']['verification_url']

# Mode B only: payment proof
if 'provider_payment' in result['proof']:
    amount = result['proof']['provider_payment']['parsed_fields']['amount']
    print(f"Payment proven: {amount} EUR")
```

---

## Plans

| | Free | Pro | Enterprise | Test |
|---|------|-----|------------|------|
| **Key prefix** | `mcp_free_*` | `mcp_pro_*` | `mcp_ent_*` | `mcp_test_*` |
| **Monthly price** | Free | €29/month | €149/month | Stripe test mode |
| **Monthly quota** | 500/month | 5,000/month | 50,000/month | 100/day (no monthly quota) |
| **Overage (opt-in)** | — | 0.01 EUR/proof | 0.005 EUR/proof | — |
| **Stripe** | — | Live | Live | Test mode |
| **Card** | None | Real card | Real card | `4242 4242 4242 4242` |
| **Setup** | Email only | Checkout (subscribe) | Checkout (subscribe) | Checkout (test) |

---

## Key endpoints

```bash
# Free signup
POST https://trust.arkforge.tech/v1/keys/free-signup

# Pro/Test setup
POST https://trust.arkforge.tech/v1/keys/setup

# Proxy (Mode A and B)
POST https://trust.arkforge.tech/v1/proxy

# Buy credits (Pro/Test)
POST https://trust.arkforge.tech/v1/credits/buy

# Check balance
GET  https://trust.arkforge.tech/v1/usage

# Retrieve a proof
GET  https://trust.arkforge.tech/v1/proof/{proof_id}
GET  https://arkforge.tech/trust/v/{proof_id}          # short URL

# Public key / DID
GET  https://trust.arkforge.tech/v1/pubkey
GET  https://trust.arkforge.tech/.well-known/did.json  # W3C DID Document

# MCP Security Assessment (v1.4+)
POST https://trust.arkforge.tech/v1/assess

# Compliance Report (v1.4+) — frameworks: eu_ai_act (default), iso_42001, nist_ai_rmf, soc2_readiness
POST https://trust.arkforge.tech/v1/compliance-report
# Body: {"framework": "eu_ai_act"|"iso_42001"|"nist_ai_rmf"|"soc2_readiness", "date_from": "...", "date_to": "..."}
```

---

## Chain hash formulas

### Mode A (spec 1.1)
```
chain_hash = SHA256(
    request_hash +
    response_hash +
    transaction_id +
    timestamp +
    buyer_fingerprint +
    seller
    [+ upstream_timestamp]   ← included only if present in proof
)
```
**Proves:** transaction — does not prove payment.

### Mode B (spec 2.0)
```
chain_hash = SHA256(
    request_hash +
    response_hash +
    transaction_id +
    timestamp +
    buyer_fingerprint +
    seller +
    [upstream_timestamp +]   ← included only if present in proof
    receipt_content_hash     ← SHA-256 of the Stripe receipt
)
```
**Proves:** transaction + payment.

---

## Autonomous agent — full lifecycle

**One-time human setup → then fully autonomous**

```
Human (once)   →  Stripe Checkout   →  Subscription active + key delivered by email
Agent (always) →  /v1/usage         →  Check monthly quota
               →  /v1/proxy         →  Execute + get proof (within monthly quota)
               →  /v1/credits/buy   →  Buy overage credits if opt-in enabled
```

```python
class AutonomousAgent:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}

    def execute(self, target, payload):
        return requests.post(
            "https://trust.arkforge.tech/v1/proxy",
            headers=self.headers,
            json={"target": target, "payload": payload}
        ).json()

agent = AutonomousAgent("mcp_pro_xxx...")
result = agent.execute("https://provider.com/api", {"task": "analyze"})
```

No browser required after the initial subscription setup.

| Step | Who | Endpoint |
|------|-----|----------|
| Subscribe (once) | Human | `POST /v1/keys/setup` → Stripe Checkout |
| Execute | Agent | `POST /v1/proxy` → included in monthly quota |
| Overage credits (opt-in) | Agent | `POST /v1/credits/buy` → off-session card charge |

**Automatic email alerts:**

| Event | Email sent |
|-------|-----------|
| 80% monthly quota consumed | "Quota alert" |
| Overage started (opt-in) | "Overage billing active" |
| 80% of overage cap | "Overage alert" (24h cooldown) |
| Overage cap reached | "Requests blocked" |

---

## Verify a proof

```bash
curl -sO https://raw.githubusercontent.com/ark-forge/trust-layer/main/scripts/verify_proof.py
python3 verify_proof.py prf_xxx                          # all witnesses
python3 verify_proof.py prf_xxx --disclose fields.json   # + disclosed fields
```

Exit 0 only if every applicable check passes and at least one independent witness confirms
the proof. A proof whose batch has not closed yet exits non-zero with
`NOT INDEPENDENTLY VERIFIED` — wait for the batch, it is at most 10 minutes.

### Self-consistency by hand (spec 3.0)

The chain hash is the Merkle root of the published per-field commitments, so no field value
is needed:

```bash
curl -s https://trust.arkforge.tech/v1/proof/prf_xxx > proof.json
jq -r '.commitments'  proof.json    # published, one per chain field
jq -r '.hashes.chain' proof.json    # their RFC 6962 Merkle root, fields sorted
jq -r '.batch_anchor' proof.json    # inclusion proof down from the anchored batch root
```

Recomputing it proves consistency, not truth. The evidence is the RFC 3161 timestamp and the
Rekor entry on the batch root — see the user guide for doing those by hand.

### Disclose one field to a counterparty

```bash
curl -s -H "X-Api-Key: $KEY" https://trust.arkforge.tech/v1/proof/prf_xxx/full \
  | jq '{disclosed: {seller: {nonce: .commitment_nonces.seller, value: .chain_data.seller}}}' \
  > fields.json
```

Send `fields.json`. Every field left out stays hidden behind its own nonce.

---

## Quick checklist

```
1. [ ] API key obtained (free / test / pro)
2. [ ] Code updated (5 lines)
3. [ ] Mode chosen (A or B)
4. [ ] Test call successful (proof_id received)
5. [ ] Public verification OK
```

---

**Full guide:** [user-guide.md](./user-guide.md)
