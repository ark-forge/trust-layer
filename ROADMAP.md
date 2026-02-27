# ArkForge Trust Layer — Roadmap

## Vision

ArkForge is a **digital notary** for agent-to-agent transactions. Like a real-world notary, ArkForge doesn't hold money, doesn't take sides, and doesn't resolve disputes. It **records what happened**, signs it, timestamps it, and stores it immutably. In case of dispute, the proof serves whoever is right.

## Core principle

A notary records what the parties presented, signs the document, and if someone lied — the notarized document becomes evidence against them.

ArkForge works the same way:
- The client provides a receipt URL for their payment
- ArkForge fetches the receipt directly from the PSP (Stripe, blockchain explorer, etc.)
- ArkForge forwards the request, hashes the response
- The proof binds everything: verified receipt + request + response + timestamp + signature
- The provider receives the proof and can verify the receipt themselves — that's their responsibility

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

## Phase 1 — Receipt verification via public URL

**Goal:** Any client can call any API through ArkForge with a payment receipt. ArkForge fetches and verifies the receipt from the PSP. No provider onboarding required. Zero friction — one curl, nothing else.

### How it works

The client sends a request with a `receipt_url` — a public URL hosted by the PSP (not by the client or the provider):

```json
{
  "target": "https://provider.com/api/endpoint",
  "payload": {"repo_url": "https://github.com/owner/repo"},
  "payment_evidence": {
    "type": "stripe",
    "receipt_url": "https://pay.stripe.com/receipts/payment/CAcaFwo..."
  }
}
```

ArkForge:
1. **Fetches** the `receipt_url` directly from the PSP (Stripe, block explorer, etc.)
2. **Hashes** the raw receipt content (SHA-256 — immutable snapshot, this is the proof)
3. **Parses** key fields (amount, status, date, currency) — deterministic parser with LLM fallback (Haiku) if parsing fails
4. Forwards the request to the target API
5. Hashes the response
6. Creates the proof: `receipt_content_hash` + `request_hash` + `response_hash` + timestamp + signature

The receipt is fetched from an **independent third party** (the PSP), not from the client. ArkForge doesn't trust the client — it verifies at the source.

### Parsing resilience

The raw HTML hash is always valid regardless of parsing success. Field extraction uses two layers:
1. **Deterministic parser** (regex/BeautifulSoup) — fast, free, handles 99%+ of cases
2. **LLM fallback** (Haiku) — activated only when the deterministic parser fails (~0.001$/call, negligible)

Stripe rarely changes receipt formats (legal documents, not UI). Monitoring detects parsing failures in real-time.

### Evolution path: Stripe API (post-adoption)

Once clients have adopted the service and have existing accounts, Phase 1 can optionally migrate to **Stripe API verification** — the client provides a restricted read-only key once, ArkForge calls `GET /v1/charges/{id}` for structured JSON. More robust, no HTML parsing, but requires a one-time setup step. This is a natural evolution, not a launch requirement.

### Preferred PSPs (verified receipts)

PSPs with publicly accessible receipt URLs. ArkForge fetches, reads, and hashes the content directly:

| PSP | Receipt URL format | What ArkForge reads |
|-----|-------------------|-------------------|
| **Stripe** | `pay.stripe.com/receipts/...` | Amount, status, date, currency |
| **Blockchain** | `etherscan.io/tx/0xabc...` (or any explorer) | Amount, from, to, confirmations, block |
| **PayPal** | `paypal.com/activity/payment/...` | Amount, status, date |

These are the **recommended** payment methods. The receipt is hosted by the PSP, publicly accessible, and independently verifiable. ArkForge fetches it directly — no trust in the client required.

The proof marks these as: `payment_verification: "fetched"`

### Declarative fallback (other PSPs)

For PSPs without public receipt URLs (bank transfers, invoices, prepaid credits, etc.), the client provides payment metadata. ArkForge hashes it but **cannot independently verify** it:

```json
{
  "payment_evidence": {
    "type": "sepa",
    "reference": "TRANSFER-2026-0227-XYZ",
    "amount": 1.00,
    "currency": "eur"
  }
}
```

ArkForge hashes and stores this as-is. The proof marks it clearly as: `payment_verification: "declared"`

| Verification level | Meaning | PSPs |
|-------------------|---------|------|
| **`fetched`** | ArkForge fetched and verified the receipt from the PSP | Stripe, blockchain, PayPal |
| **`declared`** | Client provided metadata, ArkForge stored it immutably but did not verify | SEPA, invoice, prepaid, other |

The distinction is explicit in the proof. Consumers of the proof know exactly what ArkForge verified vs. what the client declared.

### The proof is neutral

| Scenario | What the proof shows | Who wins |
|----------|---------------------|----------|
| Client really paid (fetched receipt) | Receipt from Stripe confirms payment | Client |
| Client provides fake receipt URL | ArkForge fetch fails or content doesn't match | Client exposed |
| Client provides real receipt for wrong provider | Receipt is in the proof — provider checks and sees it's not for them | Provider |
| Provider denies delivery | Response `200 OK` with data, hashed and signed | Client |
| Provider sent garbage | Response content is hashed — proof shows what was returned | Client |

The proof doesn't judge. It records. The provider receives the proof and decides whether the receipt is valid for them — that's their responsibility, not ArkForge's.

### No provider onboarding

The provider doesn't need to register, connect Stripe, or know ArkForge exists. The client specifies the target URL. ArkForge is a transparent proxy — the provider receives a normal API call.

| Marketplace | ArkForge |
|-------------|----------|
| Provider registers | Provider doesn't know ArkForge exists |
| Platform lists providers | Client chooses their own API |
| Platform intermediates payments | Client pays provider directly |
| Platform takes a cut of provider revenue | ArkForge charges for the proof only |

### What ArkForge charges for

ArkForge charges the client for the **proof service** — not for the provider's API:
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

### Three proof strengths

| Mode | Payment evidence | Proof level |
|------|-----------------|-------------|
| **Unregistered + preferred PSP** (Phase 1) | ArkForge fetched receipt from PSP | `fetched` — independently verified |
| **Unregistered + other PSP** (Phase 1) | Client-provided metadata | `declared` — stored immutably, not verified |
| **Registered provider** (Phase 2) | ArkForge orchestrated the payment | `witnessed` — ArkForge created the payment |

All three produce a valid, signed, timestamped proof. The difference is clearly marked in the proof so consumers know exactly what level of payment verification was performed.

---

## Phase 3 — Multi-PSP orchestration

**Goal:** Registered providers can accept payments through any supported PSP, not just Stripe.

| PSP | Orchestration method | Status |
|-----|---------------------|--------|
| **Stripe Connect** | Direct charges | Phase 2 |
| **Blockchain** | Smart contract or direct transfer verification | Phase 3 |
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
| v2.0 (Phase 1) | `payment_evidence` object, `receipt_content_hash` in chain, `payment_verification` level (`fetched` / `declared`) |
| v2.1 (Phase 2) | `payment_verification: "witnessed"` level, Stripe Connect witness |
| v3.0 (Phase 3) | Multi-PSP orchestrated payment witnesses |

Spec changes follow [semver](https://semver.org/). Breaking changes (chain hash formula) = major version. New optional fields = minor version.

---

## Contributing

Building an agent that needs verifiable execution? Want to route your API calls through ArkForge? Have a PSP adapter idea?

[Open an issue](https://github.com/ark-forge/trust-layer/issues) or [email us](mailto:contact@arkforge.fr).
