# Changelog

All notable changes to Trust Layer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [1.3.48] — 2026-05-05

### Added
- non-repudiation positioning — tagline + CTA banner

---

## [1.3.47] — 2026-05-05

### Fixed
- force test mode for RFC 2606 reserved email domains at source

---

## [1.3.46] — 2026-05-05

### Tests
- add scanner_pro_subscription routing regression test

---

## [1.3.45] — 2026-05-04

### Fixed
- handle scanner_pro_subscription in checkout webhook handler
- fix dns.resolver import scope in _verify_mx

---

## [1.3.44] — 2026-05-03

### Fixed
- add DNS MX validation to reject fake email domains
- add DNS MX validation to reject fake email domains

---

## [1.3.43] — 2026-05-03

_(no user-facing changes)_

---

## [1.3.42] — 2026-05-03

### Fixed
- update test email domain to non-blocked domain after disposable email blocklist
- route Scanner Pro through Checkout Sessions with real 14-day trial + block disposable emails

---

## [1.3.41] — 2026-05-03

### Fixed
- add honeypot anti-bot check to signup endpoints
- add MCP_SCAN_PINGS_LOG to config exports
- add rate limiting to /v1/keys/setup endpoint

### Documentation
- add CTEF constraint_evaluation mapping + tier_upgrade_proof v0.3.2 notes

### Internal
- upgrade dependencies — cryptography 46→47, fastapi 0.135→0.136, stripe 15.0→15.1, uvicorn 0.42→0.46

---

## [1.3.41] — 2026-05-02

### Added
- CTEF cross-implementation reference in user-guide: constraint_evaluation field mapping (AgentGraph→ArkForge), `no_critical_findings` enforcement gate, `tier_upgrade_proof` composable envelope example
- document v0.3.2 alignment: depth-first proof-stripping, canonical-bytes-diff fixture, 3 constraint_evaluation test vectors (within-limit/near-miss/exceeded)

---

## [1.3.40] — 2026-04-24

### Fixed
- add UTM tracking to README and email template links

---

## [1.3.39] — 2026-04-24

### Fixed
- add upgrade_url to free-signup API response
- add UTM tracking to Stripe checkout cancel, portal return, and abandoned checkout email URLs

---

## [1.3.38] — 2026-04-23

### Fixed
- checkout abandonment recovery + email resolution fallback

---

## [1.3.37] — 2026-04-23

### Added
- record web signups in MCP registration_log for register_free_key_calls_web

### Fixed
- add Pro upgrade CTA to free welcome email

---

## [1.3.36] — 2026-04-16

### Fixed
- filter internal/test scans from cta_impression metrics

---

## [1.3.35] — 2026-04-16

_(no user-facing changes)_

---

## [1.3.34] — 2026-04-14

### Added
- add POST /api/register endpoint for MCP phone-home registration

---

## [1.3.33] — 2026-04-10

### Added
- log tool_names and plan in scan_events.jsonl

---

## [1.3.32] — 2026-04-09

_(no user-facing changes)_

---

## [1.3.31] — 2026-04-09

### Fixed
- dynamic FAILOVER_MODE via state file — eliminates stale systemd env var

---

## [1.3.30] — 2026-04-09

### Fixed
- add User-Agent to all raw urllib requests
- add User-Agent header to prevent 403 from empty UA filter
- always return dict from req() to prevent AttributeError
- always expose mode/write_enabled, harden smoke test
- always expose mode and write_enabled fields

---

## [1.3.29] — 2026-04-09

### Added
- add server-side scan counter to /v1/stats + scan_events.jsonl

---

## [1.3.28] — 2026-04-08

### Added
- add POST /v1/contact enterprise demo request endpoint

---

## [1.3.27] — 2026-04-08

### Fixed
- use noreply@arkforge.tech as SMTP from address — arkforge.fr not verified on Resend

---

## [1.3.26] — 2026-04-07

### Fixed
- add Rekor independent verify URL to proof email
- Phase 3b — capturer stderr twine, revert on failure, idempotent on already-exists

---

## [1.3.25] — 2026-04-03

### Added
- sync arkforge-mcp à chaque livraison TL (Phase 3b)

### Fixed
- pricing URL arkforge.fr → arkforge.tech

---

## [1.3.24] — 2026-04-03

### Added
- add _links.pricing CTA in JSON responses for scan-to-pricing conversion

---

## [1.3.23] — 2026-04-03

_(no user-facing changes)_

---

## [1.3.22] — 2026-04-03

### Added
- NIST AI RMF 1.0 + SOC 2 Readiness frameworks — v1.3.23

---

## [1.3.23] — 2026-04-03

### Added
- **NIST AI RMF 1.0 compliance framework** — `POST /v1/compliance-report` accepts `"framework": "nist_ai_rmf"`.
  Maps Trust Layer proof fields to 7 subcategories across GOVERN, MAP, MEASURE, MANAGE:
  - GOVERN 1.1 Risk Policies (not_applicable), MAP 1.1 Context (spec + agent_identity),
    MAP 5.2 Risk Tracking (chain hash), MEASURE 1.1 Measurement (integrity),
    MEASURE 2.5 Monitoring (RFC 3161), MANAGE 1.3 Treatment (chain + integrity),
    MANAGE 4.1 Monitoring (proof_id + timestamp)
- **SOC 2 Readiness framework** — `POST /v1/compliance-report` accepts `"framework": "soc2_readiness"`.
  Maps to 6 AICPA Trust Service Criteria:
  - CC6.1 Logical Access (buyer_fp + seller), CC6.7 Transmission Integrity (all 3 hashes),
    CC7.2 Security Monitoring (RFC 3161), PI1.1 Completeness (integrity),
    PI1.2 Accuracy (proof_id + timestamp + fee), A1.1 Availability (not_applicable)
  - Prominent disclaimer: readiness evidence only, not a formal SOC 2 audit opinion
- 27 new tests — map_proof + generate_report + endpoint integration for both frameworks.
  522 → 549 total, 0 regressions.
- `README.md` — compliance reports section listing all 4 frameworks with curl example.
- `docs/user-guide.md` — NIST AI RMF and SOC 2 Readiness sections with criteria tables.
- `docs/quick-reference.md` — compliance endpoint updated to list all 4 frameworks.

### Changed
- `POST /v1/compliance-report` docstring: lists all 4 supported frameworks.
- `docs/user-guide.md`: "More frameworks planned" note replaced with full list.

---

## [1.3.21] — 2026-04-03

### Added
- **ISO/IEC 42001:2023 compliance framework** — `POST /v1/compliance-report` now accepts `"framework": "iso_42001"`.
  Maps Trust Layer proof fields to 6 AI Management System clauses:
  - § 6.1 Risk and Opportunity Management — `hashes.chain` presence
  - § 8.2 AI Risk Assessment — proof integrity verifiability
  - § 8.4 AI System Lifecycle Documentation — `spec_version` + `parties.agent_version`
  - § 9.1 Monitoring, Measurement and Evaluation — RFC 3161 verified timestamp
  - § 9.2 Internal Audit — cryptographic audit trail integrity
  - § 10.1 Nonconformity and Corrective Action — `not_applicable` (organisational obligation)
- 19 new tests — `ISO42001Framework.map_proof`, `generate_report`, endpoint integration.
  504 → 523 total, 0 regressions.
- `docs/user-guide.md` — full ISO 42001 section with curl + Python examples, clause coverage table.
- `docs/quick-reference.md` — compliance endpoint updated to list both frameworks.

### Changed
- `POST /v1/compliance-report` docstring updated: lists `eu_ai_act, iso_42001` as supported frameworks.
- Error message for `unknown_framework` now dynamically lists all registered frameworks (including `iso_42001`).

---

## [1.3.20] — 2026-04-03

### Fixed
- update_changelog.py reçoit HEAD + label séparé — le tag n'existe pas encore au moment de l'appel

### Documentation
- fix proof index version reference (v1.4.0 → v1.3.18) + minor README/deps updates

---

## [1.3.19] — 2026-04-03

### Changed
- **Proof index: DualWrite resilience** — `DualWriteProofIndex` replaces pure `RedisProofIndex` when Redis is available. JSONL is now always written first (durable source of truth); Redis is written second (fast `ZRANGEBYSCORE` queries). If Redis fails mid-write, the JSONL entry is already committed — no data loss.

### Added
- **Automatic JSONL→Redis reconciliation** — two background daemon threads handle sync without operator intervention:
  - *Startup reconciliation*: full JSONL replay into Redis on every service (re)start. Recovers from Redis data loss after restart.
  - *Periodic reconciliation*: re-replays the last 25 hours of JSONL into Redis every 5 minutes. Recovers from Redis outages that occur while the service is running, without requiring a service restart.
- `DualWriteProofIndex.reconcile(since_unix=None)` — callable method for manual or scripted reconciliation.
- `backfill_proof_index.py --from-jsonl` mode — replays JSONL directly into Redis (faster than scanning proof files). Supports `--since ISO8601` for incremental reconciliation.
- Ops documentation in `docs/user-guide.md` — resilience model, reconciliation triggers, manual commands.

---

## [1.3.18] — 2026-04-03

### Added
- **`POST /v1/assess`** — MCP server security posture assessment. Analyzes a server manifest for dangerous capability patterns (`PermissionAnalyzer`: filesystem write, code execution, env access, network), tool drift (`DescriptionDriftAnalyzer`: additions/removals/description changes via `difflib`), and version regressions (`VersionTrackingAnalyzer`). Returns `risk_score` (0–100), categorized findings, and baseline diff. Baseline stored per `(api_key, server_id)` in `data/mcp_baselines/`. Rate limit: 100 calls/day per API key.
- **`POST /v1/compliance-report`** — EU AI Act compliance report. Aggregates certified proofs for an API key over a date range and maps them to 6 articles: Art. 9 (risk management), Art. 10 (data governance — not applicable), Art. 13 (transparency), Art. 14 (human oversight), Art. 17 (quality management), Art. 22 (record-keeping). Returns per-article coverage status (`covered`/`partial`/`gap`/`not_applicable`) with evidence summaries and a gaps list.
- **`ProofIndexBackend` ABC** — pluggable proof index abstraction. `RedisProofIndex` (ZADD/ZRANGEBYSCORE, 90-day TTL) + `FileProofIndex` (JSONL append, `threading.Lock`) fallback. Powers date-range queries for compliance reports without scanning all proof files.
- **`scripts/backfill_proof_index.py`** — one-shot migration to index proofs created before v1.3.18.
- **APIRouter pattern** — first use of `fastapi.APIRouter` in the codebase. New routes are isolated modules under `trust_layer/routers/`. Existing `app.py` routes are untouched.

---

## [1.3.17] — 2026-04-01

### Documentation
- ROADMAP updated to reflect implemented features: agent identity, DID binding, Platform plan, proof privacy model (`/v1/proof/{id}/full`), `/v1/proof/{id}/verify` endpoint.

---

## [1.3.16] — 2026-04-01

### Added
- Platform plan TSA routing unit tests: Platform keys skip FreeTSA, fall back to Sectigo; non-platform plans retain FreeTSA-first behaviour.
- E2E integration tests for Platform plan: key prefix detection, plan propagation to `submit_hash`, DigiCert TSA confirmed on live proof.

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
