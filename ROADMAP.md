# ArkForge Trust Layer — Roadmap

## Vision

ArkForge is a **multi-witness notarization layer** for agent-to-agent transactions. A digital notary that never trusts a single party — it crosses independent witnesses to build verifiable proof.

Today, ArkForge certifies execution and payment for its own services. Tomorrow, any API provider can plug into the Trust Layer and offer their clients verifiable proof — without ArkForge ever touching the money.

## Current state (v0.3)

**What works today:**

- Certifying proxy — any HTTPS API call becomes a proven transaction
- SHA-256 hash chain binding request, response, payment, timestamp, buyer, seller
- Ed25519 digital signature (origin authentication)
- RFC 3161 certified timestamps (FreeTSA.org)
- Archive.org snapshots (public proof persistence)
- Stripe payment as 4th witness (Pro plan)
- Free tier with 3 witnesses (no credit card required)
- Open proof specification with test vectors ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec))

**Limitation:** ArkForge is both the proxy and the payment processor. The payment proof is ArkForge's own Stripe account — not an independent witness.

---

## Phase 1 — Third-party provider onboarding

**Goal:** Any API provider can register their service on ArkForge. Clients call one endpoint, get a complete proof.

### Provider registry

Providers register with:
- Service endpoint URL
- Pricing (amount, currency)
- Public key (Ed25519) for provider-side attestation
- Payment verification config (see Phase 2)

### Single-call flow

```
Client ── one call ──→ Trust Layer
                           │
                 ┌─────────┼──────────┐
                 │         │          │
                 ▼         ▼          ▼
           1. Payment   2. Forward   3. Proof
           client→provider  request→provider  signed + timestamped
           (direct)     (API call)    (multi-witness)
```

The client makes one API call. ArkForge orchestrates payment verification, request forwarding, and proof creation. Money flows directly from client to provider — ArkForge never holds funds.

### Provider signature

Providers sign their responses with their registered Ed25519 key. ArkForge verifies the signature and includes it in the proof. This binds the provider's attestation to the transaction — they can't deny delivering.

---

## Phase 2 — Independent payment verification

**The core principle:** a Trust Layer verifies only what comes from an independent third party. Never only from the provider.

### The problem

If ArkForge only records a `receipt_id` provided by the seller, the seller can fabricate it. A notary never trusts a single party.

### PSP adapters

ArkForge verifies payments **directly with the Payment Service Provider (PSP)**, not through the seller. Each PSP type has an adapter:

| PSP | Verification method | Independence |
|-----|-------------------|--------------|
| **Blockchain** | Transaction hash verified on-chain (public ledger) | Full — no cooperation needed |
| **Stripe** | Restricted API key (`payment_intents:read` only) on provider's account | Full — ArkForge reads Stripe directly |
| **Stripe webhook** | Provider configures Stripe to also notify ArkForge | Full — confirmation comes from Stripe |
| **Open Banking** | PSD2 read-access APIs (with client consent) | Full — bank is source of truth |

Blockchain is the ideal case: publicly verifiable, no privileged access required.

### Verification levels

A proof's payment witness has a verification level:

| Level | Description | Trust |
|-------|-------------|-------|
| **L0** | Receipt ID from provider only | Insufficient — not a valid witness |
| **L1** | Provider verification endpoint | Necessary but not sufficient (same actor) |
| **L2** | PSP direct verification | **Independent witness** — the real pivot |
| **L3** | PSP verification + provider cryptographic attestation | Maximum — triple coherence |

ArkForge requires **at minimum L2** for a payment to be marked as a verified witness.

### Extended proof structure

```json
{
  "payment": {
    "provider": "stripe",
    "transaction_id": "pi_xxx",
    "amount": 1.00,
    "currency": "eur",
    "status": "succeeded",
    "verification": {
      "method": "stripe_restricted_key",
      "verified_at": "2026-...",
      "level": "L2"
    }
  },
  "provider_attestation": {
    "signature": "ed25519:...",
    "pubkey": "ed25519:...",
    "payload_hash": "sha256:..."
  }
}
```

---

## Phase 3 — Multi-PSP, payment-agnostic notarization

**Goal:** ArkForge certifies any payment type without becoming a fintech.

```
Stripe ──┐
Crypto ──┤
SEPA ────┤──→ ArkForge verifies ──→ Universal proof format
PayPal ──┤
License ─┘
```

Same proof format. Same verification algorithm. Same trust guarantees. The PSP adapter is the only thing that changes.

This is what makes ArkForge a **notary**, not a payment processor:
- A notary doesn't hold the money
- A notary doesn't choose the payment method
- A notary certifies that the transaction happened, with independent witnesses

---

## What ArkForge will never be

- **Not a marketplace** — ArkForge doesn't set prices, doesn't hold funds, doesn't intermediate disputes
- **Not a fintech** — ArkForge verifies payments, it doesn't process them
- **Not an escrow** — funds flow directly between parties, ArkForge is a witness

---

## Proof evolution (spec impact)

| Spec version | Changes |
|-------------|---------|
| v1.1 (current) | Ed25519 signature, upstream_timestamp, free tier |
| v2.0 (Phase 2) | `payment.verification` object, `provider_attestation` field |
| v3.0 (Phase 3) | Multi-PSP `payment.provider` types, verification level in chain hash |

Spec changes follow [semver](https://semver.org/). Breaking changes (chain hash formula) = major version. New optional fields = minor version.

---

## Contributing

Building an agent that needs verifiable execution? Want to plug your API into the Trust Layer? Implementing a PSP adapter?

[Open an issue](https://github.com/ark-forge/trust-layer/issues) or [email us](mailto:contact@arkforge.fr).
