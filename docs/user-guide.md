# User Guide — ArkForge Trust Layer

**Integrate and use Trust Layer in 5 minutes**

---

## What is it?

ArkForge Trust Layer adds a **verifiable cryptographic proof** to any API call.

**Before:**
```python
response = requests.post("https://provider.com/api", json={...})
# → You have the result, but no proof
```

**After:**
```python
response = requests.post("https://arkforge.tech/trust/v1/proxy",
    headers={"X-Api-Key": "mcp_xxx..."},
    json={"target": "https://provider.com/api", "payload": {...}})
# → You have the result + a verifiable cryptographic proof
```

**Effort:** ~5 lines of code changed.

---

## Autonomous agents — how budget works

Trust Layer is designed for agents that run without human intervention. Here is the complete flow:

**Step 1 — One-time manual setup (human)**

The first time, a human opens a browser, enters a card, and completes the Stripe Checkout. The card is saved in Stripe for future charges.

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/setup \
  -d '{"email": "agent@example.com", "amount": 10}'
# → {"checkout_url": "https://checkout.stripe.com/c/pay/cs_live_..."}
# Open the URL, enter card → key delivered by email
```

This is the **only human action required**.

**Step 2 — Agent runs autonomously forever**

From that point on, the agent checks its balance before each task and recharges automatically if needed — no browser, no human, no interruption.

```python
import requests

class AutonomousAgent:
    def __init__(self, api_key, min_balance=5.0, recharge_amount=10.0):
        self.api_key = api_key
        self.min_balance = min_balance
        self.recharge_amount = recharge_amount
        self.headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}

    def ensure_budget(self):
        """Recharge automatically if balance is low."""
        usage = requests.get(
            "https://arkforge.tech/trust/v1/usage",
            headers=self.headers
        ).json()

        balance = usage['credit_balance']
        if balance < self.min_balance:
            result = requests.post(
                "https://arkforge.tech/trust/v1/credits/buy",
                headers=self.headers,
                json={"amount": self.recharge_amount}
            ).json()
            # result contains: credits_added, balance, charge_id, receipt_url
            print(f"Recharged: +{result['credits_added']} EUR, new balance: {result['balance']} EUR")

    def execute(self, target, payload):
        self.ensure_budget()
        return requests.post(
            "https://arkforge.tech/trust/v1/proxy",
            headers=self.headers,
            json={"target": target, "payload": payload}
        ).json()

# The agent manages its own budget indefinitely
agent = AutonomousAgent("mcp_pro_xxx...", min_balance=5.0, recharge_amount=10.0)

while True:
    result = agent.execute("https://provider.com/api", {"task": "analyze", "data": "..."})
    proof_id = result['proof']['id']
    # → Agent runs, pays for proofs, recharges itself — zero human input
```

**What happens under the hood:**
- `POST /v1/credits/buy` triggers a Stripe off-session charge on the card saved during setup
- The saved card is charged immediately — no redirect, no browser
- Credits are added to the account instantly
- The `receipt_url` in the response is a verifiable Stripe receipt for the recharge

**Summary:**

| Step | Who | Action |
|------|-----|--------|
| Initial setup | Human | Open Stripe Checkout, subscribe (Pro €29/month or Enterprise €149/month) |
| Execute tasks | Agent | `POST /v1/proxy` — included in monthly quota |
| Overage credits (opt-in) | Agent | `POST /v1/credits/buy` — only if overage billing is enabled |

---

## Two modes

### Mode A — Transaction proof only

Use this if you want to prove that a transaction took place (no payment proof needed).

**What is proven:**
- Request sent (SHA-256 hash)
- Response received (SHA-256 hash)
- Certified timestamp (RFC 3161)
- Trust Layer signature (Ed25519)
- No payment proof

**Example:** Autonomous agent consuming a service — you just want a verifiable trace.

---

### Mode B — Transaction + payment proof

Use this if you want to prove both that a transaction took place **and** that a payment was made.

**What is proven:**
- Request sent (SHA-256 hash)
- Response received (SHA-256 hash)
- Certified timestamp (RFC 3161)
- Trust Layer signature (Ed25519)
- **Payment to the provider** (Stripe receipt hash)

**Example:** Financial audit, regulatory compliance, required payment proof.

---

## Quick start

### Step 1 — Get an API key

#### Option A — Free key (500 proofs/month)

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/free-signup \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

**Response:**
```json
{
  "api_key": "mcp_free_abc123...",
  "plan": "free",
  "limit": "500 proofs/month"
}
```

No credit card required.

---

#### Option B — Pro key (€29/month, 5,000 proofs)

##### B.1 — Test mode (for development)

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "plan": "pro",
    "mode": "test"
  }'
```

**Response:**
```json
{
  "checkout_url": "https://checkout.stripe.com/c/pay/cs_test_...",
  "plan": "pro",
  "mode": "test"
}
```

**Instructions:**
1. Open `checkout_url` in a browser
2. Test card: `4242 4242 4242 4242`
3. Expiry: any future date (e.g. 12/30)
4. CVC: any 3 digits (e.g. 123)
5. Confirm → receive `mcp_test_xxx...` by email

---

##### B.2 — Pro production (€29/month, 5,000 proofs/month)

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/setup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "plan": "pro"
  }'
```

**Response:**
```json
{
  "checkout_url": "https://checkout.stripe.com/c/pay/cs_live_...",
  "plan": "pro",
  "mode": "live"
}
```

**Instructions:**
1. Open `checkout_url` in a browser
2. Enter your real card details
3. Confirm → €29/month subscription started
4. Receive `mcp_pro_xxx...` by email

**Note:** This is the **only manual step**. Everything after is automatic.

**Overages (opt-in):** by default, requests beyond 5,000 proofs/month are rejected (HTTP 429). You can opt in to overage billing at 0.01 EUR/proof from prepaid credits — enable at `POST /v1/keys/overage`.

---

##### B.3 — Manage your subscription

Open the Stripe Billing Portal to update your payment method, download invoices, or cancel:

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/portal \
  -H "X-Api-Key: mcp_pro_xxx..." \
  -H "Content-Type: application/json" \
  -d '{}'
# Returns: {"portal_url": "https://billing.stripe.com/..."}
```

Open `portal_url` in a browser.

**Subscription lifecycle:**

| Event | What happens |
|-------|-------------|
| Subscription started | API key created and emailed |
| Monthly renewal | Key stays active, no action needed |
| Payment failed (Stripe retry) | Key stays active during retry period |
| Subscription suspended (payment exhausted) | Key deactivated (HTTP 401) |
| Payment resolved → invoice paid | **Key automatically reactivated** — no action required |
| Subscription cancelled | Key deactivated permanently |

> If your key is suspended due to a failed payment, update your card in the billing portal. Once Stripe collects the payment, your key is reactivated automatically within seconds.

---

### Step 2 — Call the Trust Layer

#### Mode A — Transaction proof

```python
import requests

TRUST_LAYER_API_KEY = "mcp_free_xxx..."  # or mcp_test_xxx or mcp_pro_xxx
TARGET_API = "https://provider.com/api/service"

response = requests.post(
    "https://arkforge.tech/trust/v1/proxy",
    headers={
        "X-Api-Key": TRUST_LAYER_API_KEY,
        "Content-Type": "application/json"
    },
    json={
        "target": TARGET_API,
        "payload": {
            "task": "analyze",
            "data": "hello world"
        },
        "description": "Compliance analysis"
    }
)

result = response.json()

# Upstream service result
service_response = result['service_response']['body']
print(f"Result: {service_response}")

# Cryptographic proof
proof = result['proof']
print(f"Proof ID: {proof['proof_id']}")
print(f"Verify at: {proof['verification_url']}")
```

**What happens:**
1. Trust Layer forwards the request to the provider
2. Trust Layer hashes request + response (SHA-256)
3. Trust Layer generates a proof with Ed25519 signature
4. You receive: result + proof

**Proof contains:**
- Unique ID (e.g. `prf_20260302_135727_5b47d5`)
- SHA-256 hash of the request
- SHA-256 hash of the response
- Certified timestamp (RFC 3161)
- Ed25519 signature
- Public verification URL

**No payment proof** (Mode A).

---

#### Mode C — Certifying an action on a third-party API (extra_headers)

Use this when the target API requires its own authentication (GitHub token, Slack token, etc.). Pass the credentials in `extra_headers` — they are forwarded to the target and included in the proof's request hash.

```python
import requests

TRUST_LAYER_API_KEY = "mcp_free_xxx..."
GITHUB_TOKEN = "ghp_xxx..."

response = requests.post(
    "https://arkforge.tech/trust/v1/proxy",
    headers={
        "X-Api-Key": TRUST_LAYER_API_KEY,
        "Content-Type": "application/json"
    },
    json={
        "target": "https://api.github.com/repos/owner/repo/issues/5/comments",
        "method": "POST",
        "payload": {"body": "Automated analysis complete — see proof below."},
        "description": "GitHub comment by autonomous agent",
        "extra_headers": {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }
    }
)

result = response.json()
proof = result['proof']
print(f"Comment posted. Proof: {proof['verification_url']}")
```

**What is certified:**
- The exact payload sent to GitHub (SHA-256 hash of request)
- GitHub's response confirming the comment was created (SHA-256 hash of response)
- Timestamp (RFC 3161) + Ed25519 signature

**Constraints on `extra_headers`:**
- Maximum **10 headers**
- Keys and values must be **strings**, values ≤ 4096 characters
- Blocked headers (silently dropped): `Host`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Content-Length`, `Content-Type`, `X-Internal-Secret`

**Security note:** `extra_headers` values are included in the request hash and therefore in the proof's chain hash. This means the token's presence is attested — but the token value itself is **not stored** by Trust Layer (only its hash contribution).

---

#### Mode B — Transaction + payment proof

```python
import requests
import stripe

# 1. Agent pays provider DIRECTLY via Stripe
stripe.api_key = "sk_test_..."  # Your Stripe key

# Note: simplified example. In practice, use a saved payment method
# (payment_method_id) and expand=["charges"] to retrieve the receipt URL.
payment = stripe.PaymentIntent.create(
    amount=500,  # 5.00 EUR in cents
    currency="eur",
    description="Analysis service",
    payment_method="pm_card_visa",  # saved payment method
    confirm=True,
    expand=["charges"]
)

receipt_url = payment.charges.data[0].receipt_url
print(f"Provider paid: {receipt_url}")

# 2. Agent requests certification from Trust Layer
# Free key is sufficient for Mode B (external payment, no credit deduction)
TRUST_LAYER_API_KEY = "mcp_free_xxx..."
TARGET_API = "https://provider.com/api/service"

response = requests.post(
    "https://arkforge.tech/trust/v1/proxy",
    headers={
        "X-Api-Key": TRUST_LAYER_API_KEY,
        "Content-Type": "application/json"
    },
    json={
        "target": TARGET_API,
        "payload": {
            "task": "analyze",
            "data": "hello world"
        },
        "description": "Analysis with payment proof",
        "provider_payment": {
            "type": "stripe",
            "receipt_url": receipt_url
        }
    }
)

result = response.json()
proof = result['proof']

print(f"Proof ID: {proof['proof_id']}")
print(f"Spec version: {proof['spec_version']}")  # → 2.0

provider_payment = proof['provider_payment']
print(f"Receipt hash: {provider_payment['receipt_content_hash']}")
print(f"Amount: {provider_payment['parsed_fields']['amount']} EUR")
print(f"Verify at: {proof['verification_url']}")
```

**What happens:**
1. Agent pays provider via Stripe (5.00 EUR)
2. Agent receives a receipt URL from Stripe
3. Agent calls Trust Layer with `provider_payment`
4. Trust Layer **independently fetches the receipt from Stripe**
5. Trust Layer **hashes the receipt** (SHA-256)
6. Trust Layer **includes the receipt hash in the chain**
7. You receive: result + proof (spec 2.0)

**Proof contains (Mode B):**
- Everything from Mode A
- Receipt URL (`https://pay.stripe.com/receipts/...`)
- Receipt hash (SHA-256 of raw content)
- Parsed fields (amount, currency, status, date)
- Spec version 2.0

**SSRF protection:** Trust Layer only fetches from whitelisted domains (`pay.stripe.com`, `receipt.stripe.com`).

---

### Step 3 — Trust Layer marks on every call

Beyond the proof object, Trust Layer watermarks every transaction at 3 levels:

**Level 1 — Digital Stamp (JSON body)**

An `_arkforge_attestation` field is injected into `service_response.body`:
```json
{
  "_arkforge_attestation": {
    "id": "prf_20260302_135727_5b47d5",
    "seal": "https://arkforge.tech/trust/v1/proof/prf_20260302_135727_5b47d5",
    "status": "VERIFIED_TRANSACTION"
  }
}
```

**Level 2 — Ghost Stamp (HTTP headers)**

Every proxy response includes `X-ArkForge-Proof`, `X-ArkForge-Verified`, `X-ArkForge-Proof-ID`, and `X-ArkForge-Trust-Link` headers — visible to gateways and middleware without body parsing.

**Level 3 — Visual Stamp (HTML proof page)**

Open `https://arkforge.tech/trust/v/{proof_id}` in a browser for a human-readable verification page with a colored badge (green = verified).

---

## Proxy limits

| Limit | Value | Error when exceeded |
|-------|-------|---------------------|
| **Target protocol** | HTTPS only | `invalid_target` 400 |
| **Methods** | `GET` or `POST` | `invalid_request` 400 |
| **Payload format** | JSON only | `invalid_request` 400 |
| **Response timeout** | **120 seconds** | `proxy_timeout` 504 — proof still issued |
| **Response stored / hashed** | **1 MB** max | Truncated at 1 MB — proof covers truncated content |
| **Daily cap** | None for Free/Pro/Enterprise — full quota usable at any time. Test keys: **100/day** | `rate_limited` 429 (test keys only) |
| **Monthly quota** | 500 / 5 000 / 50 000 (Free / Pro / Enterprise) | `rate_limited` 429 (unless overage enabled) |
| **`extra_headers` count** | Max 10 | `invalid_request` 400 |
| **`extra_headers` value length** | Max 4 096 chars | `invalid_request` 400 |

**Unsupported by the proxy:**

| Feature | Status |
|---------|--------|
| Binary payloads (`multipart/form-data`, raw bytes) | Not supported — JSON only |
| Streaming / Server-Sent Events | Not supported — full response collected before proof |
| WebSocket (`Upgrade` header) | Not supported — blocked |
| HTTP (non-TLS) targets | Not supported — HTTPS required |
| Private IPs / localhost | Blocked — SSRF protection |

**Note on response truncation:** if the target API returns more than 1 MB, the stored response is truncated. The proof's `response_hash` covers the truncated version. The full upstream response is not retrievable from Trust Layer — only the first 1 MB is stored.

**Note on the 120s timeout:** long-running target APIs (ML inference, batch jobs) may hit the timeout. In that case, Trust Layer returns `proxy_timeout` (504) but still issues a proof capturing the attempt. If this is a recurring issue, consider wrapping your target API in an async job pattern and calling Trust Layer only when the result is ready.

**Note on payload encryption:** Trust Layer certifies what it receives — it does not decrypt content. Standard REST APIs (GitHub, Stripe, OpenAI, etc.) send plaintext JSON over HTTPS: Trust Layer terminates TLS, sees the plaintext, and hashes the semantic content. If your payload is encrypted at the application layer before reaching Trust Layer, the proof certifies the ciphertext — not the plaintext content. The proof remains cryptographically valid, but cannot attest to what the payload *says* without the decryption key. This distinction matters if you need to prove specific field values (e.g. `qty=1`) in a dispute.

---

## Verify a proof

**Public URL:**
```
https://arkforge.tech/trust/v/prf_20260302_135727_5b47d5
```

**Or via API:**
```bash
curl https://arkforge.tech/trust/v1/proof/prf_20260302_135727_5b47d5
```

**2 independent witnesses:**
- Ed25519 signature (ArkForge)
- RFC 3161 timestamp (FreeTSA primary, DigiCert + Sectigo fallback — `timestamp_authority.provider` records the actual issuer)

**Independent verification (without trusting Trust Layer):**

```bash
# Fetch the proof
curl -s https://arkforge.tech/trust/v1/proof/prf_xxx > proof.json

# Extract fields
REQUEST_HASH=$(jq -r '.hashes.request' proof.json | sed 's/sha256://')
RESPONSE_HASH=$(jq -r '.hashes.response' proof.json | sed 's/sha256://')
PAYMENT_ID=$(jq -r '.certification_fee.transaction_id' proof.json)
TIMESTAMP=$(jq -r '.timestamp' proof.json)
BUYER=$(jq -r '.parties.buyer_fingerprint' proof.json)
SELLER=$(jq -r '.parties.seller' proof.json)
UPSTREAM=$(jq -r '.upstream_timestamp // empty' proof.json)

# Mode B: include receipt hash if present
RECEIPT_HASH=$(jq -r '.provider_payment.receipt_content_hash // empty' proof.json | sed 's/sha256://')

# Recompute chain hash
COMPUTED=$(echo -n "${REQUEST_HASH}${RESPONSE_HASH}${PAYMENT_ID}${TIMESTAMP}${BUYER}${SELLER}${UPSTREAM}${RECEIPT_HASH}" | sha256sum | cut -d' ' -f1)

# Compare
EXPECTED=$(jq -r '.hashes.chain' proof.json | sed 's/sha256://')
[ "$COMPUTED" = "$EXPECTED" ] && echo "VERIFIED" || echo "TAMPERED"
```

---

## Quota management

### Email alerts

ArkForge sends automatic email notifications so your agent never stops silently:

| Trigger | Email | Cooldown |
|---------|-------|---------|
| Balance drops below **1.00 EUR** (~10 proofs) after a debit | "Low credits — action required" + recharge curl | 24h |
| Call rejected due to **zero balance** (HTTP 402) | "Credits exhausted — agent stopped" + recharge curl | 24h |
| **80% of daily/monthly quota** consumed | "Quota alert" + upgrade or recharge hint | Once per threshold |
| First overage proof of the month (opt-in) | "Overage billing active — monthly quota exceeded" | Once per month |
| 80% of overage monthly cap consumed (opt-in) | "Overage alert — 80% of monthly cap used" | Once per threshold |
| Overage cap reached — requests blocked (opt-in) | "Overage cap reached — requests blocked" | Once per cap event |
| Subscription payment failed (Stripe retry pending) | *(no email — key stays active during retry period)* | — |
| Key suspended after payment exhausted | *(key returns HTTP 401 — update card in billing portal)* | — |

These emails are sent to the address used during key setup. They include a ready-to-run `curl` command to recharge or adjust settings immediately — no browser required.

---

### Check quota usage

```bash
curl https://arkforge.tech/trust/v1/usage \
  -H "X-Api-Key: mcp_pro_xxx..."
```

**Response:**
```json
{
  "plan": "pro",
  "monthly": { "used": 1250, "limit": 5000, "remaining": 3750 },
  "credit_balance": 47.5
}
```

---

### Buy credits (no browser)

After the initial setup, credits can be purchased programmatically — the card saved during checkout is charged automatically.

```bash
curl -X POST https://arkforge.tech/trust/v1/credits/buy \
  -H "X-Api-Key: mcp_pro_xxx..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 10.00}'
```

**Response:**
```json
{
  "credits_added": 10.0,
  "balance": 57.5,
  "proofs_available": 575,
  "charge_id": "ch_3T5xyz...",
  "receipt_url": "https://pay.stripe.com/receipts/..."
}
```

---

### Overage billing (opt-in, Pro/Enterprise)

By default, requests beyond your monthly quota are rejected with HTTP 429.
You can opt in to overage billing: proofs beyond your quota are debited from
your prepaid credits at the per-proof overage rate, up to a monthly cap you choose.

**Enable overage billing:**

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/overage \
  -H "X-Api-Key: mcp_pro_xxx..." \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "cap_eur": 20.00}'
```

Response:
```json
{
  "overage_enabled": true,
  "overage_cap_eur": 20.0,
  "overage_rate_per_proof": 0.01,
  "consent_at": "2026-03-04T15:30:00+00:00",
  "message": "Overage billing enabled. Proofs beyond quota billed at 0.01 EUR/proof, cap 20.00 EUR/month."
}
```

**Key parameters:**
- `enabled`: `true` to opt in, `false` to opt out (immediate effect)
- `cap_eur`: monthly spending cap for overages (€5–€100, default €20)
- Overage proofs are billed from your **prepaid credits** — not a new charge
- When the cap is reached, requests are blocked (HTTP 429) until you raise the cap or wait for the next month

**Check overage status:**

```bash
curl https://arkforge.tech/trust/v1/keys/overage \
  -H "X-Api-Key: mcp_pro_xxx..."
```

**Monitor usage with overage section:**

```bash
curl https://arkforge.tech/trust/v1/usage \
  -H "X-Api-Key: mcp_pro_xxx..."
```

Response includes an `overage` section when enabled:
```json
{
  "plan": "pro",
  "monthly": {"used": 5120, "limit": 5000, "remaining": 0},
  "overage": {
    "enabled": true,
    "cap_eur": 20.0,
    "spent_eur": 1.20,
    "count": 120,
    "remaining_eur": 18.80,
    "rate_per_proof": 0.01
  }
}
```

**Disable overage billing (effective immediately):**

```bash
curl -X POST https://arkforge.tech/trust/v1/keys/overage \
  -H "X-Api-Key: mcp_pro_xxx..." \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "cap_eur": 20.0}'
```

> **Consent stored for audit:** `consent_at` (UTC timestamp) and `consent_rate` (rate at time of consent) are preserved in your key metadata even after disabling overage. This provides an auditable record of your billing agreement.

---

### Autonomous agent with budget management

```python
import requests

class AutonomousAgent:
    def __init__(self, api_key, min_balance=5.0):
        self.api_key = api_key
        self.min_balance = min_balance
        self.headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}

    def ensure_budget(self):
        usage = requests.get(
            "https://arkforge.tech/trust/v1/usage",
            headers=self.headers
        ).json()

        if usage['credit_balance'] < self.min_balance:
            requests.post(
                "https://arkforge.tech/trust/v1/credits/buy",
                headers=self.headers,
                json={"amount": 10.0}
            )

    def execute_task(self, target, payload):
        self.ensure_budget()
        return requests.post(
            "https://arkforge.tech/trust/v1/proxy",
            headers=self.headers,
            json={"target": target, "payload": payload}
        ).json()

agent = AutonomousAgent("mcp_pro_xxx...")
result = agent.execute_task("https://provider.com/api", {"task": "analyze"})
```

---

## Mode comparison

| | Mode A | Mode B |
|-|--------|--------|
| **Proves** | Execution only | Execution + payment |
| **Spec version** | 1.1 | 2.0 |
| **Chain hash includes** | Request, response, timestamp | + Receipt hash |
| **Required key** | Free/Pro/Test | Free is sufficient |
| **Extra code** | None | 3 lines (`provider_payment`) |
| **Use case** | Traceability, audit log | Financial audit, compliance |

---

## Pricing

| Plan | Cost | Monthly quota | Key prefix |
|------|------|---------------|------------|
| **Free** | Free | 500 proofs/month | `mcp_free_*` |
| **Pro** | €29/month (+ opt-in overage €0.01/proof) | 5,000 proofs/month | `mcp_pro_*` |
| **Enterprise** | €149/month (+ opt-in overage €0.005/proof) | 50,000 proofs/month | `mcp_ent_*` |
| **Test** | Stripe test mode | 100 proofs/day | `mcp_test_*` |

Mode B can use a **Free key** — certification only, payment is external, no monthly quota consumed.

---

## Integration checklist

### Step 1 — Key
- [ ] Free (500/month), Pro (€29/month, 5,000), or Enterprise (€149/month, 50,000)?
- [ ] Test mode (development) or production?
- [ ] Email received with `mcp_xxx...`?

### Step 2 — Mode
- [ ] Mode A (transaction) or Mode B (transaction + payment)?
- [ ] If Mode B: Stripe account configured?

### Step 3 — Code
- [ ] Replace upstream URL with `https://arkforge.tech/trust/v1/proxy`
- [ ] Add `X-Api-Key` header
- [ ] Wrap payload: `{"target": "...", "payload": {...}}`
- [ ] If Mode B: add `provider_payment`
- [ ] If Mode C: add `extra_headers` with target API credentials

### Step 4 — Test
- [ ] Successful call (status 200)?
- [ ] Proof generated (`proof_id` present)?
- [ ] Public verification works?

### Step 5 — Production
- [ ] Swap Test key for Pro or Enterprise
- [ ] Monitor monthly quota (`GET /v1/usage`)
- [ ] Store proof IDs

---

## Resources

- **Full API reference**: [README.md](../README.md)
- **Proof specification**: [ark-forge/proof-spec](https://github.com/ark-forge/proof-spec)
- **Quick reference**: [quick-reference.md](./quick-reference.md)
- **Support**: contact@arkforge.fr

---

*Last updated: 2026-03-06*
