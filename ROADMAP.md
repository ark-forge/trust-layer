# ArkForge Trust Layer — Roadmap

## Vision

ArkForge is an **independent certifying proxy** for AI agent actions. It sits between your agent and any upstream API — LLM provider, MCP server, payment API, or any third-party service — records the exchange from the outside, signs it, timestamps it, and anchors it in a public append-only log. Neither the agent nor the upstream controls the proof.

ArkForge doesn't hold money, doesn't take sides, and doesn't resolve disputes. It **records what happened**. In case of dispute, the proof serves whoever is right.

## Core principle

Every AI agent action produces a cryptographic receipt — an **Agent Action Receipt (AAR)** — that proves: what was sent, what was received, when it happened, and (optionally) what was paid. The AAR is independently verifiable by any third party without trusting ArkForge's infrastructure.

ArkForge works the same way for every call:
- The client provides a receipt URL for their payment (optional)
- ArkForge fetches the receipt directly from the PSP (Stripe, blockchain explorer, etc.)
- ArkForge forwards the request, hashes the response
- The proof binds everything: verified receipt + request + response + timestamp + Ed25519 signature + Sigstore Rekor anchor
- The provider receives the proof and can verify the receipt themselves — that's their responsibility

ArkForge doesn't take sides. The proof serves the truth.

## Current state (v1.3.17)

**What works today:**

- Certifying proxy — any HTTPS API call becomes a proven transaction (Agent Action Receipt)
- SHA-256 hash chain binding request, response, payment, timestamp, buyer, seller — canonical JSON (sorted keys) for spec_version ≥ 1.2, eliminating preimage ambiguity
- Ed25519 digital signature (origin authentication)
- RFC 3161 certified timestamps — pool failover: FreeTSA (primary) → DigiCert → Sectigo. Provider recorded per-proof. Platform keys use DigiCert as primary (WebTrust-certified, enterprise SLA).
- **Sigstore Rekor** — chain hash registered in the Linux Foundation's append-only public transparency log (immutable external anchor, zero-trust verification)
- Stripe payment as witness (Pro plan — ArkForge processes payment directly)
- Free tier with 3 witnesses (Ed25519, RFC 3161, Sigstore Rekor — no credit card required)
- **14-day trial** on Pro and Enterprise plans — no credit card required at signup
- **External receipt verification** — clients attach a Stripe receipt URL, ArkForge fetches, hashes, parses, and binds it to the proof (spec v2.0)
- **MCP tool call certification** — route MCP server outbound calls through `/v1/proxy`; every `tools/call` becomes a signed AAR independently verifiable by the agent's client or auditor
- **Agent identity verification** — `agent_identity` field bound cryptographically via Ed25519 challenge-response or OATR delegation at registration time. `agent_identity_verified: true` flag in proof. `did_resolution_status: "bound"` when DID is verified, `"unverified"` when caller-declared.
- **DID binding** — supports `did:key`, `did:web`, and `did:pkh` methods. Ed25519 key formats per DID method documented (Path A: native Ed25519, Path B: JWK wrapping).
- **`/.well-known/agent.json`** (v1.4) — agent discoverability endpoint. Machine-readable description of the ArkForge certifying agent: capabilities, endpoints, proof spec version, public key.
- **Privacy model for public proofs** — `GET /v1/proof/{id}` returns only `receipt_content_hash` and `verification_status` from payment data. Receipt URL, parsed fields, buyer/seller identities, reputation scores, and certification fee are masked. Full proof available via `GET /v1/proof/{id}/full` (API key required, owner only — verified via `sha256(api_key) == buyer_fingerprint`).
- **`/v1/proof/{id}/verify`** — public endpoint to verify proof integrity without authentication. Returns chain hash validity and Sigstore Rekor anchor status.
- **Proof abuse protection** — Redis-backed auto-block on suspicious proof access patterns (HTTP 429).
- **Email lifecycle notifications** — subscription events (trial start/end, upgrade, cancel) trigger transactional emails.
- Open proof specification with test vectors ([ark-forge/proof-spec](https://github.com/ark-forge/proof-spec))

**Unlocked by Phase 1:** Any client can now prove a payment made to a third-party provider. ArkForge is no longer limited to its own payment processing. Zero provider onboarding required.

---

## Phase 1 — Receipt verification via public URL [IMPLEMENTED]

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
1. **Validates** the URL (HTTPS only, whitelisted PSP domains — SSRF protection)
2. **Fetches** the `receipt_url` directly from the PSP (Stripe, block explorer, etc.)
3. **Hashes** the raw receipt content (SHA-256 — immutable snapshot, this is the proof)
4. **Parses** key fields (amount, status, date, currency) — deterministic regex parser
5. Forwards the request to the target API
6. Hashes the response
7. Creates the proof: `receipt_content_hash` + `request_hash` + `response_hash` + timestamp + signature

The receipt is fetched from an **independent third party** (the PSP), not from the client. ArkForge doesn't trust the client — it verifies at the source.

### Parsing resilience

The raw HTML hash is always valid regardless of parsing success. Field extraction uses:
1. **Deterministic parser** (regex) — fast, free, handles standard Stripe receipt formats
2. **LLM fallback** (Haiku) — planned for Phase 1+ when the deterministic parser fails

If parsing fails, `parsing_status: "failed"` but the `receipt_content_hash` remains valid and is included in the chain hash. The proof is still useful — the receipt content is cryptographically bound even without extracted fields.

The parser architecture uses an abstract `ReceiptParser` base class with a registry. Adding a new PSP parser requires no changes to the core proxy or proof code.

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
- ArkForge → for the cryptographic proof (Free: 500/month at no cost; Pro: €29/month for 5,000; Enterprise: €149/month for 50,000; Platform: €599/month for 500,000 — platforms and AI integrators, `mcp_plat_` key prefix, DigiCert-first TSA, overage opt-in at €0.002/proof)
- Provider → for the API service (their own billing, separately)

Two billing relationships, but **one runtime flow** (one API call through ArkForge).

---

## Phase 2 — Registered providers (Stripe Connect) [PLANNED]

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

## Phase 3 — Multi-PSP orchestration [PLANNED]

**Goal:** Registered providers can accept payments through any supported PSP, not just Stripe.

| PSP | Orchestration method | Status |
|-----|---------------------|--------|
| **Stripe Connect** | Direct charges | Phase 2 |
| **Blockchain** | Smart contract or direct transfer verification | Phase 3 |
| **Open Banking (PSD2)** | Payment initiation APIs (with client consent) | Phase 3 |

The proof format remains universal. Only the PSP adapter changes.

### Storage evolution

Proofs are currently stored as immutable JSON files on disk (one file per transaction). This is correct for immutability and simplicity at current scale. Cross-proof queries (reputation scoring, dispute history, analytics) are handled by scanning the proof directory at read time, which works up to ~50k–100k proofs. Beyond that threshold, a migration to SQLite (single-file, zero-ops) or Postgres is planned — the immutability guarantee is preserved by keeping the JSON files as the source of truth and using the database as a read index only.

### TSA continuity *(implemented)*

RFC 3161 timestamps use a pool of 3 servers (FreeTSA → DigiCert → Sectigo). If FreeTSA is unavailable, DigiCert or Sectigo takes over automatically — no proof is left without a timestamp due to a single TSA outage. The `timestamp_authority.provider` field records which server was used per proof.

**eIDAS-qualified timestamps (QTSP):** for clients who require a qualified electronic timestamp under eIDAS Regulation (Article 41 — qualified evidentiary value), a QTSP-certified endpoint (e.g. Alfa Trust, Certum) can be injected as primary via three env vars (`TSA_PRIMARY_URL`, `TSA_CA_FILE`, `TSA_CERT_FILE`) — no code change required. The QTSP provider's certificates must be supplied. This is not included in standard plans; it is a custom arrangement billed separately (typical cost: ~€0.05/timestamp at volume). Available on request for any plan.

---

## Dispute Protocol [UNDER DESIGN]

**Goal:** Allow parties to formally contest a proof and have the dispute recorded on the proof itself, with fair and independent resolution.

### Current state

The dispute endpoints (`POST /v1/disputes`, `GET /v1/agent/{agent_id}/disputes`) exist and allow flagging a proof as contested. The proof record stores `disputed: true` and a `dispute_id`. However, the resolution logic currently re-checks `upstream_status_code` — a field that the provider controls. This is not a reliable basis for arbitration: the provider can return any status code, independently of whether the service was actually delivered.

Consequence: the dispute system is in place as **infrastructure** (flagging, history, proof markers) but the **resolution logic** is not yet implemented. No reputation impact from disputes currently.

### What proper arbitration requires

A fair resolution must be based on **evidence independent of both parties**:

| Evidence type | What it proves | Status |
|---------------|---------------|--------|
| Chain hash | Exact request + response + payment at time T | Already in proof |
| RFC 3161 timestamp | ArkForge recorded it at a specific time | Already in proof |
| Receipt content hash | Payment receipt content at time T | Already in proof (v2.0) |
| Response content | What the provider actually returned | Hashed in proof, raw content stored server-side |
| Arbitrator signature | Independent third party reviewed and decided | **Not yet implemented** |

### Design options being considered

1. **Timed evidence window** — both parties submit additional evidence within N days; a human reviewer from ArkForge decides, signs the resolution, and it is appended to the proof
2. **Cryptographic challenge-response** — provider must sign a "delivery confirmed" message with their key within N hours, or the dispute is upheld by default
3. **On-chain anchoring** — dispute and resolution hashed into a public ledger for immutability beyond ArkForge

### Proof spec impact

The current proof format is ready for disputes:
- `disputed` and `dispute_id` fields exist in the proof record (post-hoc metadata, not in chain hash)
- Chain hash is unaffected by a dispute — the proof itself remains valid

A future spec version (v3.x) could add a `dispute_resolution` object with an arbitrator signature, making the resolution itself cryptographically provable.

---

## What ArkForge is and isn't

| ArkForge IS | ArkForge IS NOT |
|-------------|-----------------|
| An independent certifying proxy | A marketplace |
| A proof layer for agent actions | A payment processor |
| Model-agnostic and vendor-agnostic | Stripe-dependent |
| Non-custodial | An escrow service |
| An AAR issuer (Agent Action Receipts) | A billing platform |

ArkForge records, signs, and timestamps. It doesn't hold money, set prices, list providers, or resolve disputes. The proof speaks for itself.

---

## Proof evolution (spec impact)

| Spec version | Changes |
|-------------|---------|
| v1.1 | Ed25519 signature, upstream_timestamp, free tier |
| v1.2 (current) | **Chain hash algorithm: canonical JSON** (sorted keys) instead of string concatenation — eliminates preimage ambiguity. Breaking change for proof verification; legacy path retained for spec_version 1.1. |
| v2.0 (current) | `payment_evidence` object, `receipt_content_hash` in chain hash, `payment_verification` level (`fetched` / `declared`), extensible PSP parser architecture |
| v2.1 (current) | `agent_identity` + `agent_identity_verified` fields, `did_resolution_status`, `/.well-known/agent.json` v1.4 |
| v2.2 (Phase 2) | `payment_verification: "witnessed"` level, Stripe Connect witness |
| v2.3 (planned) | **Assessment Receipt** — `assess_id` linkable to a proof chain. MCP server manifest hash in chain data. Enables cryptographic proof that a specific server manifest was certified at time T. Design foundations laid in v1.4.0 (`assess_id: asr_*` already stable). |
| v3.0 (Phase 3) | Multi-PSP orchestrated payment witnesses |
| v3.x (Dispute Protocol) | `dispute_resolution` object with arbitrator signature — resolution becomes cryptographically provable |

Spec changes follow [semver](https://semver.org/). Breaking changes (chain hash formula) = major version. New optional fields = minor version.

---

## Phase 4 — MCP Security + Compliance Intelligence [IMPLEMENTED v1.4.0]

**Goal:** Extend Trust Layer beyond transaction certification into active security posture monitoring and regulatory compliance reporting.

### MCP Security Posture Assessment (`POST /v1/assess`)

Analyzes MCP server manifests for security risks and drift between deployments.

- **Pluggable analyzer architecture** (mirrors PSP parser registry): `BaseAnalyzer` ABC + registry + `register_analyzer()`. Built-in analyzers: `PermissionAnalyzer` (dangerous capability patterns), `DescriptionDriftAnalyzer` (tool additions/removals/changes via `difflib`), `VersionTrackingAnalyzer` (version regressions).
- **Baseline per (api_key, server_id)** stored in `data/mcp_baselines/`. Every call updates the baseline and compares against the previous state.
- **Assessment artifact** (`asr_*`) stored in `data/assessments/` — stable ID for future spec v2.3 Assessment Receipt.
- **Extensibility**: new analyzers (CVE scanning, LLM-based intent analysis, OWASP mapping) require no changes to core code — subclass, implement, register.

### EU AI Act Compliance Report (`POST /v1/compliance-report`)

Aggregates certified proofs over a date range and maps them to EU AI Act articles.

- **Pluggable framework architecture**: `BaseComplianceFramework` ABC + registry + `register_framework()`. Built-in: `EUAIActFramework` v1.0.
- **Proof index** (`ProofIndexBackend` ABC) enables time-range queries without scanning all proof files. `DualWriteProofIndex` (v1.3.19+) writes to JSONL (durable) + Redis (fast queries); JSONL is source of truth, Redis is rebuilt automatically at startup and every 5 minutes. Migration path to SQLite is a new backend implementation, not a code change.
- **Article mapping** (Art. 9, 10, 13, 14, 17, 22) derived from existing proof fields — no spec change required.
- **Extensibility**: `SOC2Framework`, `ISO27001Framework`, `NISTAIRMFFramework` require only subclassing `BaseComplianceFramework`.

### Proof Index Resilience (`DualWriteProofIndex`) [IMPLEMENTED v1.3.19]

Eliminates the Redis/JSONL split-brain condition introduced in v1.3.18. JSONL is always written first; Redis is derived. Two automatic reconciliation triggers: startup (full replay) + periodic every 5 min (25h window). Manual: `backfill_proof_index.py --from-jsonl`.

---

## Contributing

Building an agent that needs verifiable execution? Want to route your API calls through ArkForge? Have a PSP adapter idea?

[Open an issue](https://github.com/ark-forge/trust-layer/issues) or [email us](mailto:contact@arkforge.tech).
