# Changelog

All notable changes to Trust Layer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [1.3.15] — 2026-03-31

### Added
- **Platform plan** — 599 EUR/month, 500,000 proofs/month, for platforms and AI integrators. API key prefix `mcp_plat_`. Overage opt-in at 0.002 EUR/proof.
- **DigiCert-first TSA routing for Platform keys** — Platform API keys skip FreeTSA and use DigiCert as primary timestamp authority. FreeTSA is a community service with no SLA; DigiCert is WebTrust-certified with enterprise-grade reliability. Fallback chain: DigiCert → Sectigo (unchanged). All other plans retain FreeTSA-first behaviour.
- Platform plan exposed in `GET /v1/pricing`.
- Stripe product + price IDs (live and test) added to vault and loaded via `config.py`.

---

## [1.3.6] — 2026-03-26

### Changed
- Upgrade stripe 14.4.1 → 15.0.0. Adapted to `StripeObject` no longer inheriting from `dict`: webhook handler uses dot notation (`event.id`, `event.type`, `event.livemode`, `event.data.object.to_dict()`); payment provider uses `customer.invoice_settings` dot notation. Updated test mocks accordingly.

---

## [1.3.2] — 2026-03-24

### Added
- `parties.did_resolution_status` field in proof receipts. `"bound"` when `agent_identity` is a cryptographically verified DID bound via Ed25519 challenge-response or OATR delegation at registration time. `"unverified"` when `agent_identity` is caller-declared without cryptographic verification. Absent if no `agent_identity` is provided.

---

## [1.3.1] — 2026-03-24

### Changed
- `GET /v1/proof/{id}` now includes `agent_identity` and `seller` in public responses. `buyer_fingerprint` remains authenticated-only. Third-party auditors and WG members can verify agent identity without API key access.

---

## [1.3.0] — 2026-03-16

### Changed
- `GET /v1/proof/{id}` no longer exposes `provider_payment` details (receipt URL, parsed fields), `parties`, `certification_fee`, `buyer_reputation_score`, or `buyer_profile_url` in public responses. Only `receipt_content_hash` and `verification_status` remain visible in `provider_payment`.

### Added
- `GET /v1/proof/{id}/full` — authenticated endpoint (API key required, owner only). Returns the complete proof including payment details, parties, and certification fee. Ownership verified via `sha256(api_key) == parties.buyer_fingerprint`.

### Security
- Payment amounts, Stripe receipt URLs, parsed payment fields, buyer/seller identities, and reputation scores are no longer publicly visible on `GET /v1/proof/{id}`.

---

## [1.2.3] — 2026-03-11

### Fixed
- CI pipeline: validate release workflow produces green run after v1.2.1/v1.2.2 CHANGELOG commit fix.

---

## [1.2.2] — 2026-03-11

### Fixed
- CI release: CHANGELOG commit moved to deploy script (pre-tag) — avoids branch protection conflict during CI.
- CI fallback PR path for CHANGELOG commit when API commit is blocked.

---

## [1.2.1] — 2026-03-11

### Security
- Dependency update: cryptography 43.0.0 → 46.0.5 — patches 3 Dependabot CVEs (cee19b8)

### Tests
- Conformance: branch chain_hash by `algorithm` field (legacy vs canonical_json) (b28ee18)

---


## [1.2.0] — 2026-03-10

### Breaking Changes
- **Chain hash algorithm changed for spec_version 1.2 / proof-spec 2.1.**
  The chain hash is now computed over a canonical JSON dict (sorted keys) instead of a raw string concatenation. This eliminates preimage ambiguity when field values contain separator characters.
  Proofs issued before v1.2.0 (spec_version 1.1) continue to verify correctly via the legacy path in `verify_proof_integrity()`.

### Security
- **CRITICAL — chain hash preimage ambiguity (CVE-equivalent).**
  String concatenation `request_hash + response_hash + payment_intent_id + ...` allowed crafted values to produce collisions. Fixed by switching to `sha256(canonical_json({...}))` for spec_version ≥ 1.2.

### Added
- `proof-spec v2.1.0` alignment: `verify_proof_integrity()` routes by `spec_version` field (1.1/2.0 → legacy, 1.2/2.1 → canonical_json).
- Conformance test suite `tests/test_spec_conformance.py`: branches chain hash computation by `algorithm` field in test vectors. 27/27 vectors pass.

---

## [1.1.20] — 2026-03-09

### Security
- Proof abuse auto-block: `proof_abuse:{ip}` checked in Redis at the top of `get_proof()`, returns HTTP 429 immediately (previously only logged).
- Dependency pinning: `requirements.txt` now uses `==` exact versions (`pip freeze`); `requirements-dev.txt` separated. Gardien Check 2 covers CVEs via `pip-audit`.
- SAST: `nosec B104` annotations on intentional host bindings (`0.0.0.0`).

---

## [1.1.19] — 2026-03-09

### Fixed
- Templates: footer link `arkforge.fr` → `arkforge.tech` (domain migration).

---

## [1.1.18] — 2026-03-09

### Fixed
- All internal URLs and redirect targets migrated `arkforge.fr/trust` → `arkforge.tech/trust` (Stripe success/cancel/return URLs, nginx redirects).

---

## [1.1.17] — 2026-03-09

### Fixed
- Domain migration `arkforge.fr` → `arkforge.tech` for all public-facing URLs.

---

## [1.1.16] — 2026-03-08

### Fixed
- Welcome email: replaced generic text with actionable first-proof example for free tier users.
- CI gate: fallback to recent runs if no run directly on `main` (handles post squash-merge PRs).

### Documentation
- README rewrite: removed internal TSA provider names; public-facing language only.

---

## [1.1.15] — 2026-03-07

### Documentation
- Mode C (`extra_headers`) usage guide, Redis env var reference, systemd `--workers 4` example.

---

## [1.1.14] — 2026-03-06

### Added
- Redis hot path rate limiting (atomic `INCR + EXPIRE`): correct shared state across multiple uvicorn workers. In-memory fallback if Redis unavailable.
- Multi-worker readiness: shared rate limit state via Redis.

---

## [1.1.13] — 2026-03-06

### Changed
- Removed daily cap for all plans (Free/Pro/Enterprise). Monthly quota only — no per-day rate restriction.

---

## [1.1.12] — 2026-03-06

### Added
- Dynamic daily cap per plan: Free=100, Pro=500, Enterprise=5,000 proofs/day.

---

## [1.1.11] — 2026-03-06

### Documentation
- `extra_headers`: forwarding credentials to target APIs documentation.
- Proxy limits: full section (timeout, payload size, methods, format, daily cap).

---

## [1.1.10] — 2026-03-06

### Added
- `extra_headers` hardening: strict header allowlist, hop-by-hop filtering, dogfooding via certified GitHub comments.

---

## [1.1.9] — 2026-03-06

_(internal version bump — no user-facing changes)_

---

## [1.1.8] — 2026-03-06

### Fixed
- Removed pay-per-use pricing model (€0.10/proof): billing now subscription-only.
- Free tier test keys updated; test suite aligned.

### Security
- SSRF expansion: CGNAT ranges, IPv4-mapped IPv6, 6to4 added to `_PRIVATE_NETWORKS` blocklist.

### Documentation
- Security: uvicorn `127.0.0.1` binding rationale, `pip-audit` integration, network exposure model.

---

## [1.1.7] — 2026-03-05

### Added
- Transactional email migrated from OVH SMTP to Resend (better deliverability, API-based).

---

## [1.1.6] — 2026-03-05

### Fixed
- Smoke tests: use `@smoke.invalid` email addresses to prevent real SMTP delivery during test runs.

---

## [1.1.4 – 1.1.5] — 2026-03-05

### Security
- API keys encrypted at rest with Fernet (AES-128). `KEYS_FERNET_KEY_FILE` env var controls key path. 7-year retention.

---

## [1.1.3] — 2026-03-05

### Added
- Staged blue/green rollout via HA infra (failover-first strategy).
- Smoke test suite: 5 post-deploy validation sections.

### Fixed
- Versioning unified: `__init__.py` auto-bumped by deploy script.
- Rollback: `git reset --hard` + post-rollback verification.

### Documentation
- User guide: subscription lifecycle, billing portal, email alerts.

---

## [1.1.1 – 1.1.2] — 2026-03-05

_(initial 1.1.x series — internal stabilisation)_

---

## [0.5.4] — 2026-03-05

### Added
- Stripe webhooks: `invoice.paid` and `invoice.payment_failed` handlers.
