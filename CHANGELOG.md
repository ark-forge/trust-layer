# Changelog

All notable changes to Trust Layer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

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

---

## [Unreleased]

_Next changes will appear here automatically._

---

## [1.2.1] — 2026-03-10

### Security
- **cryptography 43.0.0 → 46.0.5** — closes 3 Dependabot alerts:
  - HIGH: subgroup attack via missing validation on SECT curves (fixed in 46.0.5)
  - MEDIUM: vulnerable OpenSSL bundled in wheels (fixed in 43.0.1)
  - LOW: vulnerable OpenSSL bundled in wheels (fixed in 44.0.1)
  `cryptography` is not directly used by Trust Layer code (Fernet key derivation only) — no API change.
