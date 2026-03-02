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
Agent → Trust Layer (certification + payment_evidence)
        └─ Proof: request + response + timestamp + receipt
        └─ Payment proof included

Use case: financial audit, compliance, non-repudiation
```

---

## 3 steps

### 1 — Get a key

```bash
# Free (100/month)
curl -X POST https://arkforge.fr/trust/v1/keys/free-signup \
  -d '{"email": "you@example.com"}'

# Pro Test (development)
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -d '{"email": "you@example.com", "amount": 10, "mode": "test"}'
# → Open checkout_url, card 4242 4242 4242 4242

# Pro Prod (production)
curl -X POST https://arkforge.fr/trust/v1/keys/setup \
  -d '{"email": "you@example.com", "amount": 10}'
# → Open checkout_url, real card
```

---

### 2 — Modify your code

#### Mode A (transaction only)

```python
# BEFORE
response = requests.post("https://provider.com/api", json={...})

# AFTER
response = requests.post(
    "https://arkforge.fr/trust/v1/proxy",
    headers={"X-Api-Key": "mcp_xxx..."},
    json={
        "target": "https://provider.com/api",
        "payload": {...}
    }
)
```

#### Mode B (transaction + payment)

```python
# 1. Pay provider via Stripe
payment = stripe.PaymentIntent.create(amount=500, ..., expand=["charges"])
receipt_url = payment.charges.data[0].receipt_url

# 2. Certification with payment proof
response = requests.post(
    "https://arkforge.fr/trust/v1/proxy",
    headers={"X-Api-Key": "mcp_xxx..."},  # Free key is sufficient
    json={
        "target": "https://provider.com/api",
        "payload": {...},
        "payment_evidence": {           # ← 3 extra lines
            "type": "stripe",
            "receipt_url": receipt_url
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
if 'payment_evidence' in result['proof']:
    amount = result['proof']['payment_evidence']['parsed_fields']['amount']
    print(f"Payment proven: {amount} EUR")
```

---

## Plans

| | Free | Test | Pro |
|---|------|------|-----|
| **Key prefix** | `mcp_free_*` | `mcp_test_*` | `mcp_pro_*` |
| **Cost** | Free | 0.10 EUR/proof (test) | 0.10 EUR/proof (prod) |
| **Limit** | 100/month | Unlimited | Unlimited |
| **Stripe** | — | Test mode | Live mode |
| **Card** | None | `4242 4242 4242 4242` | Real card |
| **Setup** | Email | Checkout (once) | Checkout (once) |
| **Recharge** | No | Automatic | Automatic |

---

## Key endpoints

```bash
# Free signup
POST https://arkforge.fr/trust/v1/keys/free-signup

# Pro/Test setup
POST https://arkforge.fr/trust/v1/keys/setup

# Proxy (Mode A and B)
POST https://arkforge.fr/trust/v1/proxy

# Buy credits (Pro/Test)
POST https://arkforge.fr/trust/v1/credits/buy

# Check balance
GET  https://arkforge.fr/trust/v1/usage

# Retrieve a proof
GET  https://arkforge.fr/trust/v1/proof/{proof_id}
GET  https://arkforge.fr/trust/v/{proof_id}          # short URL
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
    receipt_content_hash     ← SHA-256 of the Stripe receipt
)
```
**Proves:** transaction + payment.

---

## Autonomous agent (auto-recharge)

```python
class SmartAgent:
    def ensure_budget(self):
        balance = requests.get(
            "https://arkforge.fr/trust/v1/usage",
            headers={"X-Api-Key": self.api_key}
        ).json()['credit_balance']

        if balance < 5.0:
            requests.post(
                "https://arkforge.fr/trust/v1/credits/buy",
                headers={"X-Api-Key": self.api_key},
                json={"amount": 10.0}
            )

agent = SmartAgent("mcp_pro_xxx...")
agent.ensure_budget()  # Recharges automatically if needed
```

No browser required after the initial setup.

---

## Verify a proof (bash)

```bash
# Independent chain hash recomputation
curl -s https://arkforge.fr/trust/v1/proof/prf_xxx > proof.json

REQUEST_HASH=$(jq -r '.hashes.request' proof.json | sed 's/sha256://')
RESPONSE_HASH=$(jq -r '.hashes.response' proof.json | sed 's/sha256://')
PAYMENT_ID=$(jq -r '.payment.transaction_id' proof.json)
TIMESTAMP=$(jq -r '.timestamp' proof.json)
BUYER=$(jq -r '.parties.buyer_fingerprint' proof.json)
SELLER=$(jq -r '.parties.seller' proof.json)
RECEIPT_HASH=$(jq -r '.payment_evidence.receipt_content_hash // empty' proof.json | sed 's/sha256://')

COMPUTED=$(echo -n "${REQUEST_HASH}${RESPONSE_HASH}${PAYMENT_ID}${TIMESTAMP}${BUYER}${SELLER}${RECEIPT_HASH}" | sha256sum | cut -d' ' -f1)
EXPECTED=$(jq -r '.hashes.chain' proof.json | sed 's/sha256://')

[ "$COMPUTED" = "$EXPECTED" ] && echo "VERIFIED" || echo "TAMPERED"
```

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
