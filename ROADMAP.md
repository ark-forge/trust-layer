# ArkForge Trust Layer — Roadmap

## Vision

ArkForge is a **digital notary** for agent-to-agent transactions. Like a real-world notary, ArkForge doesn't hold money, doesn't verify bank accounts, and doesn't take sides. It **records what happened**, signs it, timestamps it, and stores it immutably. In case of dispute, the proof serves whoever is right.

## Core principle

A notary doesn't call the bank to check if the transfer is real. A notary records what the parties presented, signs the document, and if someone lied — the notarized document becomes evidence against them.

ArkForge works the same way:
- The client declares a payment (receipt, transaction ID, tx hash — anything)
- ArkForge hashes it, forwards the request, hashes the response
- The proof binds everything: declared payment + request + response + timestamp + signature
- If the payment evidence is real → it proves the client paid
- If the payment evidence is fake → it proves the client lied

ArkForge doesn't take sides. The proof serves the truth.

## Current state (v0.3)

**What works today:**

- Certifying proxy — any HTTPS API call becomes a proven transaction
- SHA-256 hash chain binding request, response, payment, timestamp, buyer, seller
- Ed25519 digital signature (origin authentication)
- RFC 3161 certified timestamps (FreeTSA.org)
- Archive.org snapshots (public proof persistence)
- Stripe payment as witness (Pro plan — ArkForge processes payment directly)
- Free tier with 3 witnesses (no credit card required)
- Open proof specification with test vectors ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec))

**Current limitation:** ArkForge is both the proxy and the payment processor. Works for ArkForge's own services, but doesn't scale to third-party providers.

---

## Phase 1 — Declarative payment evidence

**Goal:** Any client can call any API through ArkForge with payment evidence. No provider onboarding required.

### How it works

The client sends a request with `payment_evidence` — a declaration of payment to the provider:

```json
{
  "target": "https://provider.com/api/endpoint",
  "payload": {"repo_url": "https://github.com/owner/repo"},
  "payment_evidence": {
    "type": "stripe",
    "transaction_id": "pi_3abc...",
    "receipt_url": "https://pay.stripe.com/receipts/...",
    "amount": 1.00,
    "currency": "eur"
  }
}
```

ArkForge:
1. Hashes the `payment_evidence` (immutable, whatever the client declared)
2. Forwards the request to the target API
3. Hashes the response
4. Creates the proof: `payment_evidence_hash` + `request_hash` + `response_hash` + timestamp + signature

### The proof is neutral

| Scenario | What the proof shows | Who wins |
|----------|---------------------|----------|
| Client really paid | `payment_evidence` contains a real Stripe PI → verifiable | Client |
| Client faked receipt | `payment_evidence` contains a fake PI → verifiable | Provider |
| Provider denies delivery | Response `200 OK` with data, hashed and signed | Client |
| Provider sent garbage | Response hashed — content is in the proof | Client |

The proof doesn't judge. It records. Courts, auditors, and agents can verify independently.

### Payment-agnostic by design

The `payment_evidence` field accepts anything:

| Type | Example | How to verify independently |
|------|---------|---------------------------|
| `stripe` | `pi_3abc...` + receipt URL | Stripe API or receipt URL |
| `blockchain` | `0xabc...` tx hash + chain | Any block explorer |
| `sepa` | Transfer reference + IBAN | Bank statement |
| `paypal` | Transaction ID | PayPal dashboard |
| `invoice` | Invoice number + amount | Provider's billing system |
| `prepaid` | Account ID + credit balance | Provider's API |
| `free` | `null` | N/A — no payment claimed |

ArkForge doesn't care what the payment type is. It hashes the evidence and stores it immutably. Verification is done by the party that needs it, using the original payment system.

### No provider onboarding

The provider doesn't need to register, connect Stripe, or know ArkForge exists. The client specifies the target URL. ArkForge is a transparent proxy — the provider receives a normal API call.

This is the fundamental difference with a marketplace:

| Marketplace | ArkForge |
|-------------|----------|
| Provider registers | Provider doesn't know ArkForge exists |
| Platform lists providers | Client chooses their own API |
| Platform intermediates payments | Client pays provider directly |
| Platform takes a cut of provider revenue | ArkForge charges for the proof only |

### What ArkForge charges for

ArkForge charges the client for the **proof service** — not for the provider's API. The client pays:
- ArkForge → for the cryptographic proof (current pricing: 0.50 EUR/proof or free tier)
- Provider → for the API service (their own billing, separately)

Two billing relationships, but **one runtime flow** (one API call through ArkForge).

---

## Phase 2 — Registered providers (Stripe Connect)

**Goal:** Providers who want the simplest experience for their agent clients can register with ArkForge. One payment, one call, complete proof.

### Why a provider would register

An agent that consumes APIs needs:
1. A way to pay the provider programmatically
2. A way to verify payment before the provider delivers
3. A proof that it all happened

Without ArkForge, the provider builds their own billing system for agent clients. With ArkForge, the provider connects once (Stripe Connect OAuth) and ArkForge handles agent billing.

### How it works

```
Agent client ── one call ──→ ArkForge
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                    ▼           ▼           ▼
              Stripe Connect   Forward     Proof
              direct charge    to provider  signed + timestamped
              client→provider  (API call)
              (ArkForge fee)
```

- Money goes directly to the provider's Stripe account (direct charge)
- ArkForge takes an application fee for the proof service
- ArkForge witnessed the payment (it created the PaymentIntent) → strongest proof level
- Legal compliance: Stripe holds the payment facilitator license, not ArkForge
- Non-custodial: funds never sit in ArkForge's account

### Two proof strengths

| Mode | Payment evidence | Proof strength |
|------|-----------------|----------------|
| **Unregistered provider** (Phase 1) | Client-declared (`payment_evidence` field) | Declarative — immutable record of what the client claimed |
| **Registered provider** (Phase 2) | ArkForge-orchestrated (Stripe Connect) | Witnessed — ArkForge directly observed the payment |

Both produce a valid, signed, timestamped proof. The difference is whether ArkForge can attest that the payment happened (witnessed) or only that the client declared it happened (declarative).

---

## Phase 3 — Multi-PSP orchestration

**Goal:** Registered providers can accept payments through any supported PSP, not just Stripe.

| PSP | Orchestration method | Status |
|-----|---------------------|--------|
| **Stripe Connect** | Direct charges | Phase 2 |
| **Blockchain** | Smart contract escrow or direct transfer verification | Phase 3 |
| **Open Banking (PSD2)** | Payment initiation APIs (with client consent) | Phase 3 |

The proof format remains universal. Only the PSP adapter changes.

---

## What ArkForge is and isn't

| ArkForge IS | ArkForge IS NOT |
|-------------|-----------------|
| A digital notary | A marketplace |
| A certifying proxy | A payment processor |
| Payment-agnostic | Stripe-dependent |
| Non-custodial | An escrow service |
| A proof layer | A billing platform |

ArkForge records, signs, and timestamps. It doesn't hold money, set prices, list providers, or resolve disputes. The proof speaks for itself.

---

## Proof evolution (spec impact)

| Spec version | Changes |
|-------------|---------|
| v1.1 (current) | Ed25519 signature, upstream_timestamp, free tier |
| v2.0 (Phase 1) | `payment_evidence` object (client-declared), `payment_evidence_hash` in chain |
| v2.1 (Phase 2) | `payment.witnessed: true/false` field, Stripe Connect witness |
| v3.0 (Phase 3) | Multi-PSP `payment_evidence.type` values, orchestrated payment witnesses |

Spec changes follow [semver](https://semver.org/). Breaking changes (chain hash formula) = major version. New optional fields = minor version.

---

## Contributing

Building an agent that needs verifiable execution? Want to route your API calls through ArkForge? Have a PSP adapter idea?

[Open an issue](https://github.com/ark-forge/trust-layer/issues) or [email us](mailto:contact@arkforge.fr).
