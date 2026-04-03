"""EU AI Act compliance report generation.

Pluggable compliance framework architecture mirrors receipt.py:
- BaseComplianceFramework (ABC) + registry + register_framework()
- Built-in: EUAIActFramework (Articles 9, 10, 13, 14, 17, 22)

To add a new framework (SOC2, ISO27001, NIST AI RMF...):
1. Subclass BaseComplianceFramework
2. Set `name` and `version`
3. Implement `map_proof()` and `generate_report()`
4. Call `register_framework(YourFramework())` at module level

Article mapping notes:
- Art. 10 (Data Governance): not_applicable — organisational obligation,
  not verifiable from transaction proofs.
- All other articles map to proof fields: hashes, parties, timestamp_authority.
- Status levels: covered | partial | gap | not_applicable
"""

import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .proofs import load_proof, verify_proof_integrity

logger = logging.getLogger("trust_layer.compliance")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ArticleMapping:
    article: str         # e.g. "Art. 9"
    title: str           # human-readable
    status: str          # covered | partial | gap | not_applicable
    evidence: str        # human-readable explanation
    proof_ids: list[str] = field(default_factory=list)
    reason: Optional[str] = None  # for not_applicable


@dataclass
class ComplianceReport:
    report_id: str
    framework: str
    framework_version: str
    date_range: dict
    proof_count: int
    articles: list[ArticleMapping]
    gaps: list[str]
    summary: dict
    coverage_since: Optional[str] = None


# ---------------------------------------------------------------------------
# Abstract framework
# ---------------------------------------------------------------------------

class BaseComplianceFramework(ABC):
    """Abstract compliance framework.

    To add a new framework:
    1. Subclass BaseComplianceFramework
    2. Set `name` and `version`
    3. Implement `map_proof()` and `generate_report()`
    4. Call `register_framework(YourFramework())` at module level
    """

    name: str
    version: str

    @abstractmethod
    def map_proof(self, proof: dict) -> list[ArticleMapping]:
        """Map a single proof to article-level evidence."""
        ...

    @abstractmethod
    def generate_report(
        self,
        proof_ids: list[str],
        date_range: dict,
        coverage_since: Optional[str] = None,
    ) -> ComplianceReport:
        """Aggregate all proof mappings into a full compliance report."""
        ...


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------

_FRAMEWORK_REGISTRY: dict[str, BaseComplianceFramework] = {}


def register_framework(framework: BaseComplianceFramework) -> None:
    """Register a compliance framework. Called at module level."""
    _FRAMEWORK_REGISTRY[framework.name] = framework


def get_framework(name: str) -> Optional[BaseComplianceFramework]:
    """Get a framework by name."""
    return _FRAMEWORK_REGISTRY.get(name)


def list_frameworks() -> list[str]:
    """Return all registered framework names."""
    return list(_FRAMEWORK_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_report_id() -> str:
    """Generate report ID: rpt_YYYYMMDD_HHMMSS_<6hex>."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d_%H%M%S")
    rand = secrets.token_hex(3)
    return f"rpt_{ts}_{rand}"


def _article_dict(m: ArticleMapping) -> dict:
    d: dict = {
        "article": m.article,
        "title": m.title,
        "status": m.status,
        "evidence": m.evidence,
        "proof_count": len(m.proof_ids),
    }
    if m.proof_ids:
        d["proof_sample"] = m.proof_ids[:3]
    if m.reason:
        d["reason"] = m.reason
    return d


# ---------------------------------------------------------------------------
# EU AI Act Framework
# ---------------------------------------------------------------------------

_EU_AI_ACT_ARTICLES = [
    ("Art. 9",  "Risk Management System"),
    ("Art. 10", "Data and Data Governance"),
    ("Art. 13", "Transparency and Provision of Information"),
    ("Art. 14", "Human Oversight"),
    ("Art. 17", "Quality Management System"),
    ("Art. 22", "Record-keeping"),
]


class EUAIActFramework(BaseComplianceFramework):
    """EU AI Act compliance framework (Regulation 2024/1689).

    Maps Trust Layer proof fields to verifiable obligations.
    Organisational obligations (Art. 10) are marked not_applicable
    as they cannot be derived from transaction proofs.

    Applicability note: Art. 9, 13, 14, 17 apply to high-risk AI systems
    under Annex III. Record-keeping (Art. 22) applies broadly.
    """

    name = "eu_ai_act"
    version = "1.0"

    def map_proof(self, proof: dict) -> list[ArticleMapping]:
        """Map a single proof to EU AI Act articles.

        Returns one ArticleMapping per article (6 total).
        """
        parties = proof.get("parties", {})
        hashes = proof.get("hashes", {})
        tsa = proof.get("timestamp_authority", {})
        proof_id = proof.get("proof_id", "")

        mappings = []

        # Art. 9 — Risk Management: proof exists with valid chain hash
        chain_ok = bool(hashes.get("chain"))
        mappings.append(ArticleMapping(
            article="Art. 9",
            title="Risk Management System",
            status="covered" if chain_ok else "gap",
            evidence="Cryptographic chain hash documents AI system action" if chain_ok
                     else "Proof missing chain hash",
            proof_ids=[proof_id] if chain_ok else [],
        ))

        # Art. 10 — Data Governance: not verifiable from transaction proofs
        mappings.append(ArticleMapping(
            article="Art. 10",
            title="Data and Data Governance",
            status="not_applicable",
            evidence="Organisational obligation — not verifiable from transaction proofs",
            reason="Art. 10 requires data governance policies and dataset documentation. "
                   "These are organisational controls that exist outside transaction records.",
        ))

        # Art. 13 — Transparency: agent identified, seller recorded, timestamp present
        agent_id = parties.get("agent_identity")
        seller = parties.get("seller")
        tsa_ok = tsa.get("status") == "verified"
        transparency_fields = sum([bool(agent_id), bool(seller), tsa_ok])
        if transparency_fields == 3:
            t_status = "covered"
            t_evidence = "Agent identity, seller, and RFC 3161 timestamp present"
        elif transparency_fields >= 1:
            t_status = "partial"
            missing = []
            if not agent_id:
                missing.append("agent_identity")
            if not seller:
                missing.append("seller")
            if not tsa_ok:
                missing.append("verified timestamp")
            t_evidence = f"Partial transparency: missing {', '.join(missing)}"
        else:
            t_status = "gap"
            t_evidence = "No transparency evidence (agent identity, seller, timestamp)"
        mappings.append(ArticleMapping(
            article="Art. 13",
            title="Transparency and Provision of Information",
            status=t_status,
            evidence=t_evidence,
            proof_ids=[proof_id] if t_status != "gap" else [],
        ))

        # Art. 14 — Human Oversight: agent_identity_verified or buyer_fingerprint present
        agent_verified = parties.get("agent_identity_verified") is True
        buyer_fp = parties.get("buyer_fingerprint", "")
        if agent_verified:
            ho_status = "covered"
            ho_evidence = "Agent identity cryptographically verified (Ed25519/DID)"
        elif buyer_fp:
            ho_status = "partial"
            ho_evidence = "Human-controlled API key used (buyer_fingerprint present); agent not DID-verified"
        else:
            ho_status = "gap"
            ho_evidence = "No human oversight evidence"
        mappings.append(ArticleMapping(
            article="Art. 14",
            title="Human Oversight",
            status=ho_status,
            evidence=ho_evidence,
            proof_ids=[proof_id] if ho_status != "gap" else [],
        ))

        # Art. 17 — Quality Management: proof integrity verifiable
        integrity_ok = verify_proof_integrity(proof)
        mappings.append(ArticleMapping(
            article="Art. 17",
            title="Quality Management System",
            status="covered" if integrity_ok else "gap",
            evidence="Proof chain hash integrity verified" if integrity_ok
                     else "Proof chain hash failed verification",
            proof_ids=[proof_id] if integrity_ok else [],
        ))

        # Art. 22 — Record-keeping: proof exists and is timestamped
        ts = proof.get("timestamp", "")
        rk_status = "covered" if (proof_id and ts) else "gap"
        mappings.append(ArticleMapping(
            article="Art. 22",
            title="Record-keeping",
            status=rk_status,
            evidence=f"Immutable proof record with timestamp {ts[:10] if ts else 'missing'}",
            proof_ids=[proof_id] if rk_status == "covered" else [],
        ))

        return mappings

    def generate_report(
        self,
        proof_ids: list[str],
        date_range: dict,
        coverage_since: Optional[str] = None,
    ) -> ComplianceReport:
        """Aggregate article mappings across all proofs in the date range."""
        # Accumulate per-article: proof_ids and worst status
        _STATUS_RANK = {"gap": 0, "partial": 1, "covered": 2, "not_applicable": 3}

        article_meta = {art: (title, "not_applicable", "", [])
                        for art, title in _EU_AI_ACT_ARTICLES}
        # (title, best_status_rank, evidence_for_best, proof_ids)
        article_acc: dict[str, dict] = {
            art: {"title": title, "rank": -1, "evidence": "", "proof_ids": [], "reason": None}
            for art, title in _EU_AI_ACT_ARTICLES
        }

        proofs_loaded = 0
        for pid in proof_ids:
            proof = load_proof(pid)
            if proof is None:
                continue
            proofs_loaded += 1
            for mapping in self.map_proof(proof):
                acc = article_acc[mapping.article]
                rank = _STATUS_RANK.get(mapping.status, -1)
                if mapping.status == "not_applicable":
                    # not_applicable is fixed — set once
                    if acc["rank"] == -1:
                        acc["rank"] = rank
                        acc["evidence"] = mapping.evidence
                        acc["reason"] = mapping.reason
                elif rank > acc["rank"]:
                    acc["rank"] = rank
                    acc["evidence"] = mapping.evidence
                if mapping.proof_ids:
                    acc["proof_ids"].extend(mapping.proof_ids)

        # Build article list
        _RANK_TO_STATUS = {v: k for k, v in _STATUS_RANK.items()}
        articles = []
        gaps = []
        summary = {"covered": 0, "partial": 0, "gap": 0, "not_applicable": 0}

        for art, title in _EU_AI_ACT_ARTICLES:
            acc = article_acc[art]
            rank = acc["rank"]
            if rank == -1:
                # No proofs analyzed — all articles default to gap (except Art. 10)
                if art == "Art. 10":
                    status = "not_applicable"
                    evidence = article_meta[art][2] or (
                        "Organisational obligation — not verifiable from transaction proofs"
                    )
                else:
                    status = "gap"
                    evidence = "No proofs analyzed in the selected date range"
            else:
                status = _RANK_TO_STATUS[rank]
                evidence = acc["evidence"]

            am = ArticleMapping(
                article=art,
                title=title,
                status=status,
                evidence=evidence,
                proof_ids=list(dict.fromkeys(acc["proof_ids"]))[:10],  # dedup, cap at 10
                reason=acc.get("reason"),
            )
            articles.append(am)
            summary[status] = summary.get(status, 0) + 1
            if status == "gap":
                gaps.append(f"{art}: {title}")

        return ComplianceReport(
            report_id=generate_report_id(),
            framework=self.name,
            framework_version=self.version,
            date_range=date_range,
            proof_count=proofs_loaded,
            articles=articles,
            gaps=gaps,
            summary=summary,
            coverage_since=coverage_since,
        )


register_framework(EUAIActFramework())


# ---------------------------------------------------------------------------
# ISO/IEC 42001:2023 Framework
# ---------------------------------------------------------------------------

_ISO42001_CLAUSES = [
    ("§ 6.1",  "Risk and Opportunity Management"),
    ("§ 8.2",  "AI Risk Assessment"),
    ("§ 8.4",  "AI System Lifecycle Documentation"),
    ("§ 9.1",  "Monitoring, Measurement and Evaluation"),
    ("§ 9.2",  "Internal Audit"),
    ("§ 10.1", "Nonconformity and Corrective Action"),
]


class ISO42001Framework(BaseComplianceFramework):
    """ISO/IEC 42001:2023 AI Management System compliance framework.

    Maps Trust Layer proof fields to verifiable management system obligations.
    Organisational obligations (§ 10.1) are marked not_applicable as they
    cannot be derived from transaction proofs.

    Clause coverage:
    - § 6.1: Risk tracking — chain hash presence documents AI action
    - § 8.2: Risk assessment — proof integrity verifiability
    - § 8.4: Lifecycle documentation — spec_version + agent_version
    - § 9.1: Monitoring — RFC 3161 verified timestamp
    - § 9.2: Internal audit — cryptographic audit trail integrity
    - § 10.1: Nonconformity — not_applicable (organisational obligation)
    """

    name = "iso_42001"
    version = "1.0"

    def map_proof(self, proof: dict) -> list[ArticleMapping]:
        """Map a single proof to ISO/IEC 42001 clauses.

        Returns one ArticleMapping per clause (6 total).
        """
        hashes = proof.get("hashes", {})
        parties = proof.get("parties", {})
        tsa = proof.get("timestamp_authority", {})
        proof_id = proof.get("proof_id", "")

        mappings = []

        # § 6.1 — Risk and Opportunity Management: chain hash documents AI action
        chain_ok = bool(hashes.get("chain"))
        mappings.append(ArticleMapping(
            article="§ 6.1",
            title="Risk and Opportunity Management",
            status="covered" if chain_ok else "gap",
            evidence="Cryptographic chain hash documents AI action for risk tracking" if chain_ok
                     else "Proof missing chain hash — risk tracking gap",
            proof_ids=[proof_id] if chain_ok else [],
        ))

        # § 8.2 — AI Risk Assessment: integrity verifiability
        integrity_ok = verify_proof_integrity(proof)
        if integrity_ok:
            r82_status = "covered"
            r82_evidence = "Proof chain hash integrity verified — AI risk evidence is tamper-proof"
        elif chain_ok:
            r82_status = "partial"
            r82_evidence = "Chain hash present but integrity check failed — evidence may be compromised"
        else:
            r82_status = "gap"
            r82_evidence = "No chain hash — AI risk assessment evidence unavailable"
        mappings.append(ArticleMapping(
            article="§ 8.2",
            title="AI Risk Assessment",
            status=r82_status,
            evidence=r82_evidence,
            proof_ids=[proof_id] if r82_status == "covered" else [],
        ))

        # § 8.4 — AI System Lifecycle Documentation: spec_version + agent_version
        spec_version = proof.get("spec_version", "")
        agent_version = parties.get("agent_version", "")
        if spec_version and agent_version:
            r84_status = "covered"
            r84_evidence = (
                f"Proof spec v{spec_version} + agent v{agent_version} — system lifecycle documented"
            )
        elif spec_version or agent_version:
            r84_status = "partial"
            missing = []
            if not spec_version:
                missing.append("spec_version")
            if not agent_version:
                missing.append("agent_version")
            r84_evidence = f"Partial lifecycle documentation: missing {', '.join(missing)}"
        else:
            r84_status = "gap"
            r84_evidence = "No version information — AI system lifecycle not documented in proofs"
        mappings.append(ArticleMapping(
            article="§ 8.4",
            title="AI System Lifecycle Documentation",
            status=r84_status,
            evidence=r84_evidence,
            proof_ids=[proof_id] if r84_status != "gap" else [],
        ))

        # § 9.1 — Monitoring, Measurement and Evaluation: RFC 3161 verified timestamp
        tsa_ok = tsa.get("status") == "verified"
        ts = proof.get("timestamp", "")
        if tsa_ok:
            r91_status = "covered"
            r91_evidence = "RFC 3161 verified timestamp — monitoring evidence is non-repudiable"
        elif ts:
            r91_status = "partial"
            r91_evidence = (
                "Timestamp present but RFC 3161 verification failed — "
                "monitoring evidence not independently verifiable"
            )
        else:
            r91_status = "gap"
            r91_evidence = "No timestamp — monitoring and measurement evidence unavailable"
        mappings.append(ArticleMapping(
            article="§ 9.1",
            title="Monitoring, Measurement and Evaluation",
            status=r91_status,
            evidence=r91_evidence,
            proof_ids=[proof_id] if r91_status != "gap" else [],
        ))

        # § 9.2 — Internal Audit: proof integrity provides verifiable audit trail
        mappings.append(ArticleMapping(
            article="§ 9.2",
            title="Internal Audit",
            status="covered" if integrity_ok else "gap",
            evidence=(
                "Immutable cryptographic audit trail — all proofs independently verifiable"
                if integrity_ok
                else "Proof integrity failed — audit trail reliability compromised"
            ),
            proof_ids=[proof_id] if integrity_ok else [],
        ))

        # § 10.1 — Nonconformity and Corrective Action: organisational obligation
        mappings.append(ArticleMapping(
            article="§ 10.1",
            title="Nonconformity and Corrective Action",
            status="not_applicable",
            evidence="Organisational obligation — not verifiable from transaction proofs",
            reason=(
                "§ 10.1 requires documented procedures for identifying and addressing "
                "nonconformities. These are internal management controls that exist "
                "outside transaction records."
            ),
        ))

        return mappings

    def generate_report(
        self,
        proof_ids: list[str],
        date_range: dict,
        coverage_since: Optional[str] = None,
    ) -> ComplianceReport:
        """Aggregate clause mappings across all proofs in the date range."""
        _STATUS_RANK = {"gap": 0, "partial": 1, "covered": 2, "not_applicable": 3}

        clause_acc: dict[str, dict] = {
            clause: {"title": title, "rank": -1, "evidence": "", "proof_ids": [], "reason": None}
            for clause, title in _ISO42001_CLAUSES
        }

        proofs_loaded = 0
        for pid in proof_ids:
            proof = load_proof(pid)
            if proof is None:
                continue
            proofs_loaded += 1
            for mapping in self.map_proof(proof):
                acc = clause_acc[mapping.article]
                rank = _STATUS_RANK.get(mapping.status, -1)
                if mapping.status == "not_applicable":
                    if acc["rank"] == -1:
                        acc["rank"] = rank
                        acc["evidence"] = mapping.evidence
                        acc["reason"] = mapping.reason
                elif rank > acc["rank"]:
                    acc["rank"] = rank
                    acc["evidence"] = mapping.evidence
                if mapping.proof_ids:
                    acc["proof_ids"].extend(mapping.proof_ids)

        _RANK_TO_STATUS = {v: k for k, v in _STATUS_RANK.items()}
        articles = []
        gaps = []
        summary = {"covered": 0, "partial": 0, "gap": 0, "not_applicable": 0}

        for clause, title in _ISO42001_CLAUSES:
            acc = clause_acc[clause]
            rank = acc["rank"]
            if rank == -1:
                if clause == "§ 10.1":
                    status = "not_applicable"
                    evidence = "Organisational obligation — not verifiable from transaction proofs"
                else:
                    status = "gap"
                    evidence = "No proofs analyzed in the selected date range"
            else:
                status = _RANK_TO_STATUS[rank]
                evidence = acc["evidence"]

            am = ArticleMapping(
                article=clause,
                title=title,
                status=status,
                evidence=evidence,
                proof_ids=list(dict.fromkeys(acc["proof_ids"]))[:10],  # dedup, cap at 10
                reason=acc.get("reason"),
            )
            articles.append(am)
            summary[status] = summary.get(status, 0) + 1
            if status == "gap":
                gaps.append(f"{clause}: {title}")

        return ComplianceReport(
            report_id=generate_report_id(),
            framework=self.name,
            framework_version=self.version,
            date_range=date_range,
            proof_count=proofs_loaded,
            articles=articles,
            gaps=gaps,
            summary=summary,
            coverage_since=coverage_since,
        )


register_framework(ISO42001Framework())


# ---------------------------------------------------------------------------
# NIST AI RMF 1.0 Framework
# ---------------------------------------------------------------------------

_NIST_AI_RMF_SUBCATEGORIES = [
    ("GOVERN 1.1", "AI Risk Policies and Procedures"),
    ("MAP 1.1",    "AI System Context Established"),
    ("MAP 5.2",    "AI Risk Tracking Practices"),
    ("MEASURE 1.1","Risk Measurement Methods"),
    ("MEASURE 2.5","AI System Performance Monitored"),
    ("MANAGE 1.3", "Risk Treatment Documented"),
    ("MANAGE 4.1", "Risk Monitoring Established"),
]


class NISTAIRMFFramework(BaseComplianceFramework):
    """NIST AI Risk Management Framework 1.0 compliance mapping.

    Maps Trust Layer proof fields to verifiable RMF subcategories across
    the four core functions: GOVERN, MAP, MEASURE, MANAGE.

    Organisational subcategories (GOVERN 1.1) are marked not_applicable
    as they require policy documentation outside transaction records.

    Reference: NIST AI 100-1 (2023), https://doi.org/10.6028/NIST.AI.100-1
    """

    name = "nist_ai_rmf"
    version = "1.0"

    def map_proof(self, proof: dict) -> list[ArticleMapping]:
        """Map a single proof to NIST AI RMF subcategories.

        Returns one ArticleMapping per subcategory (7 total).
        """
        hashes = proof.get("hashes", {})
        parties = proof.get("parties", {})
        tsa = proof.get("timestamp_authority", {})
        proof_id = proof.get("proof_id", "")

        mappings = []

        # GOVERN 1.1 — AI Risk Policies: organisational obligation
        mappings.append(ArticleMapping(
            article="GOVERN 1.1",
            title="AI Risk Policies and Procedures",
            status="not_applicable",
            evidence="Organisational obligation — not verifiable from transaction proofs",
            reason=(
                "GOVERN 1.1 requires documented AI risk policies and governance structures. "
                "These are organisational controls that exist outside transaction records."
            ),
        ))

        # MAP 1.1 — AI System Context: spec_version + agent_identity document the system
        spec_version = proof.get("spec_version", "")
        agent_identity = parties.get("agent_identity", "")
        if spec_version and agent_identity:
            m11_status = "covered"
            m11_evidence = (
                f"AI system context documented: spec v{spec_version}, "
                f"agent identity {str(agent_identity)[:40]}"
            )
        elif spec_version or agent_identity:
            m11_status = "partial"
            missing = []
            if not spec_version:
                missing.append("spec_version")
            if not agent_identity:
                missing.append("agent_identity")
            m11_evidence = f"Partial context: missing {', '.join(missing)}"
        else:
            m11_status = "gap"
            m11_evidence = "No system context documented in proof"
        mappings.append(ArticleMapping(
            article="MAP 1.1",
            title="AI System Context Established",
            status=m11_status,
            evidence=m11_evidence,
            proof_ids=[proof_id] if m11_status != "gap" else [],
        ))

        # MAP 5.2 — AI Risk Tracking: chain hash documents each AI action
        chain_ok = bool(hashes.get("chain"))
        mappings.append(ArticleMapping(
            article="MAP 5.2",
            title="AI Risk Tracking Practices",
            status="covered" if chain_ok else "gap",
            evidence="Cryptographic chain hash tracks each AI action for risk traceability"
                     if chain_ok else "Proof missing chain hash — risk tracking gap",
            proof_ids=[proof_id] if chain_ok else [],
        ))

        # MEASURE 1.1 — Risk Measurement Methods: integrity verifiable = measurement established
        integrity_ok = verify_proof_integrity(proof)
        if integrity_ok:
            ms11_status = "covered"
            ms11_evidence = "Proof chain hash integrity verified — risk measurement is tamper-proof"
        elif chain_ok:
            ms11_status = "partial"
            ms11_evidence = "Chain hash present but integrity check failed — measurement reliability compromised"
        else:
            ms11_status = "gap"
            ms11_evidence = "No chain hash — risk measurement evidence unavailable"
        mappings.append(ArticleMapping(
            article="MEASURE 1.1",
            title="Risk Measurement Methods",
            status=ms11_status,
            evidence=ms11_evidence,
            proof_ids=[proof_id] if ms11_status == "covered" else [],
        ))

        # MEASURE 2.5 — AI System Performance Monitored: RFC 3161 verified timestamp
        tsa_ok = tsa.get("status") == "verified"
        ts = proof.get("timestamp", "")
        if tsa_ok:
            ms25_status = "covered"
            ms25_evidence = "RFC 3161 verified timestamp — performance monitoring evidence is non-repudiable"
        elif ts:
            ms25_status = "partial"
            ms25_evidence = (
                "Timestamp present but RFC 3161 verification failed — "
                "monitoring evidence not independently verifiable"
            )
        else:
            ms25_status = "gap"
            ms25_evidence = "No timestamp — AI system performance monitoring evidence unavailable"
        mappings.append(ArticleMapping(
            article="MEASURE 2.5",
            title="AI System Performance Monitored",
            status=ms25_status,
            evidence=ms25_evidence,
            proof_ids=[proof_id] if ms25_status != "gap" else [],
        ))

        # MANAGE 1.3 — Risk Treatment Documented: chain hash + integrity = treatment on record
        if integrity_ok:
            mg13_status = "covered"
            mg13_evidence = "Risk treatment documented: verified proof chain records the AI action and its context"
        elif chain_ok:
            mg13_status = "partial"
            mg13_evidence = "Chain hash present but integrity failed — risk treatment record may be compromised"
        else:
            mg13_status = "gap"
            mg13_evidence = "No chain hash — risk treatment not documented"
        mappings.append(ArticleMapping(
            article="MANAGE 1.3",
            title="Risk Treatment Documented",
            status=mg13_status,
            evidence=mg13_evidence,
            proof_ids=[proof_id] if mg13_status == "covered" else [],
        ))

        # MANAGE 4.1 — Risk Monitoring Established: proof_id + timestamp = monitoring record exists
        ts_present = bool(ts)
        if proof_id and ts_present:
            mg41_status = "covered"
            mg41_evidence = f"Immutable monitoring record established: proof {proof_id[:24]} at {ts[:10]}"
        elif proof_id or ts_present:
            mg41_status = "partial"
            mg41_evidence = "Partial monitoring record: " + ("proof_id present" if proof_id else "timestamp present")
        else:
            mg41_status = "gap"
            mg41_evidence = "No monitoring record established"
        mappings.append(ArticleMapping(
            article="MANAGE 4.1",
            title="Risk Monitoring Established",
            status=mg41_status,
            evidence=mg41_evidence,
            proof_ids=[proof_id] if mg41_status != "gap" else [],
        ))

        return mappings

    def generate_report(
        self,
        proof_ids: list[str],
        date_range: dict,
        coverage_since: Optional[str] = None,
    ) -> ComplianceReport:
        """Aggregate subcategory mappings across all proofs in the date range."""
        _STATUS_RANK = {"gap": 0, "partial": 1, "covered": 2, "not_applicable": 3}

        acc: dict[str, dict] = {
            sub: {"title": title, "rank": -1, "evidence": "", "proof_ids": [], "reason": None}
            for sub, title in _NIST_AI_RMF_SUBCATEGORIES
        }

        proofs_loaded = 0
        for pid in proof_ids:
            proof = load_proof(pid)
            if proof is None:
                continue
            proofs_loaded += 1
            for mapping in self.map_proof(proof):
                entry = acc[mapping.article]
                rank = _STATUS_RANK.get(mapping.status, -1)
                if mapping.status == "not_applicable":
                    if entry["rank"] == -1:
                        entry["rank"] = rank
                        entry["evidence"] = mapping.evidence
                        entry["reason"] = mapping.reason
                elif rank > entry["rank"]:
                    entry["rank"] = rank
                    entry["evidence"] = mapping.evidence
                if mapping.proof_ids:
                    entry["proof_ids"].extend(mapping.proof_ids)

        _RANK_TO_STATUS = {v: k for k, v in _STATUS_RANK.items()}
        articles = []
        gaps = []
        summary = {"covered": 0, "partial": 0, "gap": 0, "not_applicable": 0}

        for sub, title in _NIST_AI_RMF_SUBCATEGORIES:
            entry = acc[sub]
            rank = entry["rank"]
            if rank == -1:
                if sub == "GOVERN 1.1":
                    status = "not_applicable"
                    evidence = "Organisational obligation — not verifiable from transaction proofs"
                else:
                    status = "gap"
                    evidence = "No proofs analyzed in the selected date range"
            else:
                status = _RANK_TO_STATUS[rank]
                evidence = entry["evidence"]

            am = ArticleMapping(
                article=sub,
                title=title,
                status=status,
                evidence=evidence,
                proof_ids=list(dict.fromkeys(entry["proof_ids"]))[:10],
                reason=entry.get("reason"),
            )
            articles.append(am)
            summary[status] = summary.get(status, 0) + 1
            if status == "gap":
                gaps.append(f"{sub}: {title}")

        return ComplianceReport(
            report_id=generate_report_id(),
            framework=self.name,
            framework_version=self.version,
            date_range=date_range,
            proof_count=proofs_loaded,
            articles=articles,
            gaps=gaps,
            summary=summary,
            coverage_since=coverage_since,
        )


register_framework(NISTAIRMFFramework())


# ---------------------------------------------------------------------------
# SOC 2 Readiness Framework
# ---------------------------------------------------------------------------

_SOC2_CRITERIA = [
    ("CC6.1", "Logical Access Controls"),
    ("CC6.7", "Transmission and Movement Integrity"),
    ("CC7.2", "Security Event Monitoring"),
    ("PI1.1", "Processing Integrity — Completeness"),
    ("PI1.2", "Processing Integrity — Accuracy"),
    ("A1.1",  "Availability Monitoring"),
]


class SOC2ReadinessFramework(BaseComplianceFramework):
    """SOC 2 Readiness mapping — Trust Service Criteria evidence.

    Maps Trust Layer proof fields to SOC 2 Trust Service Criteria (TSC)
    as *readiness evidence*, not as a formal SOC 2 audit report.

    IMPORTANT: This framework produces readiness evidence, not a SOC 2
    audit opinion. A formal SOC 2 Type II report requires an independent
    CPA firm accredited by the AICPA. Use this report to prepare for
    an audit, not to replace one.

    Criteria covered:
    - CC6.1: Logical access — API key auth chain (buyer_fingerprint + seller)
    - CC6.7: Transmission integrity — chain hash protects data in transit
    - CC7.2: Security event monitoring — RFC 3161 timestamped events
    - PI1.1: Processing completeness — proof chain hash integrity
    - PI1.2: Processing accuracy — proof_id + timestamp + certification_fee status
    - A1.1: Availability monitoring — not_applicable (infrastructure concern)

    Reference: AICPA Trust Services Criteria (2017, updated 2022)
    """

    name = "soc2_readiness"
    version = "1.0"

    def map_proof(self, proof: dict) -> list[ArticleMapping]:
        """Map a single proof to SOC 2 Trust Service Criteria.

        Returns one ArticleMapping per criterion (6 total).
        """
        hashes = proof.get("hashes", {})
        parties = proof.get("parties", {})
        tsa = proof.get("timestamp_authority", {})
        fee = proof.get("certification_fee", {})
        proof_id = proof.get("proof_id", "")

        mappings = []

        # CC6.1 — Logical Access Controls: API key auth chain documented
        buyer_fp = parties.get("buyer_fingerprint", "")
        seller = parties.get("seller", "")
        if buyer_fp and seller:
            cc61_status = "covered"
            cc61_evidence = "Logical access documented: buyer fingerprint + seller identity in proof"
        elif buyer_fp or seller:
            cc61_status = "partial"
            missing = []
            if not buyer_fp:
                missing.append("buyer_fingerprint")
            if not seller:
                missing.append("seller")
            cc61_evidence = f"Partial access evidence: missing {', '.join(missing)}"
        else:
            cc61_status = "gap"
            cc61_evidence = "No access control evidence in proof"
        mappings.append(ArticleMapping(
            article="CC6.1",
            title="Logical Access Controls",
            status=cc61_status,
            evidence=cc61_evidence,
            proof_ids=[proof_id] if cc61_status != "gap" else [],
        ))

        # CC6.7 — Transmission Integrity: chain hash protects data in transit
        chain_ok = bool(hashes.get("chain"))
        req_ok = bool(hashes.get("request"))
        resp_ok = bool(hashes.get("response"))
        if chain_ok and req_ok and resp_ok:
            cc67_status = "covered"
            cc67_evidence = "Request, response, and chain hashes present — transmission integrity verifiable"
        elif chain_ok or (req_ok and resp_ok):
            cc67_status = "partial"
            cc67_evidence = "Partial hash coverage — transmission integrity partially verifiable"
        else:
            cc67_status = "gap"
            cc67_evidence = "No hashes present — transmission integrity not verifiable"
        mappings.append(ArticleMapping(
            article="CC6.7",
            title="Transmission and Movement Integrity",
            status=cc67_status,
            evidence=cc67_evidence,
            proof_ids=[proof_id] if cc67_status != "gap" else [],
        ))

        # CC7.2 — Security Event Monitoring: RFC 3161 timestamped events
        tsa_ok = tsa.get("status") == "verified"
        ts = proof.get("timestamp", "")
        if tsa_ok:
            cc72_status = "covered"
            cc72_evidence = "Security events monitored: RFC 3161 verified timestamp on every proof"
        elif ts:
            cc72_status = "partial"
            cc72_evidence = (
                "Timestamp present but RFC 3161 verification failed — "
                "event monitoring not independently verifiable"
            )
        else:
            cc72_status = "gap"
            cc72_evidence = "No timestamp — security event monitoring evidence unavailable"
        mappings.append(ArticleMapping(
            article="CC7.2",
            title="Security Event Monitoring",
            status=cc72_status,
            evidence=cc72_evidence,
            proof_ids=[proof_id] if cc72_status != "gap" else [],
        ))

        # PI1.1 — Processing Integrity — Completeness: proof chain integrity verifiable
        integrity_ok = verify_proof_integrity(proof)
        if integrity_ok:
            pi11_status = "covered"
            pi11_evidence = "Processing completeness verified: chain hash integrity check passed"
        elif chain_ok:
            pi11_status = "partial"
            pi11_evidence = "Chain hash present but integrity check failed — completeness unverifiable"
        else:
            pi11_status = "gap"
            pi11_evidence = "No chain hash — processing completeness cannot be verified"
        mappings.append(ArticleMapping(
            article="PI1.1",
            title="Processing Integrity — Completeness",
            status=pi11_status,
            evidence=pi11_evidence,
            proof_ids=[proof_id] if pi11_status == "covered" else [],
        ))

        # PI1.2 — Processing Accuracy: proof_id + timestamp + fee status
        fee_ok = fee.get("status") == "succeeded"
        ts_ok = bool(ts)
        if proof_id and ts_ok and fee_ok:
            pi12_status = "covered"
            pi12_evidence = "Processing accuracy documented: proof ID, timestamp, and succeeded certification fee"
        elif proof_id and ts_ok:
            pi12_status = "partial"
            missing_pi = []
            if not fee_ok:
                missing_pi.append("certification_fee.status=succeeded")
            pi12_evidence = f"Partial accuracy evidence: missing {', '.join(missing_pi)}"
        else:
            pi12_status = "gap"
            pi12_evidence = "Insufficient fields to establish processing accuracy"
        mappings.append(ArticleMapping(
            article="PI1.2",
            title="Processing Integrity — Accuracy",
            status=pi12_status,
            evidence=pi12_evidence,
            proof_ids=[proof_id] if pi12_status != "gap" else [],
        ))

        # A1.1 — Availability Monitoring: infrastructure concern, not derivable from proofs
        mappings.append(ArticleMapping(
            article="A1.1",
            title="Availability Monitoring",
            status="not_applicable",
            evidence="Infrastructure obligation — not verifiable from transaction proofs",
            reason=(
                "A1.1 requires capacity planning, availability monitoring, and incident "
                "response for the infrastructure layer. These controls exist outside "
                "transaction records and require infrastructure-level evidence."
            ),
        ))

        return mappings

    def generate_report(
        self,
        proof_ids: list[str],
        date_range: dict,
        coverage_since: Optional[str] = None,
    ) -> ComplianceReport:
        """Aggregate TSC criterion mappings across all proofs in the date range."""
        _STATUS_RANK = {"gap": 0, "partial": 1, "covered": 2, "not_applicable": 3}

        acc: dict[str, dict] = {
            crit: {"title": title, "rank": -1, "evidence": "", "proof_ids": [], "reason": None}
            for crit, title in _SOC2_CRITERIA
        }

        proofs_loaded = 0
        for pid in proof_ids:
            proof = load_proof(pid)
            if proof is None:
                continue
            proofs_loaded += 1
            for mapping in self.map_proof(proof):
                entry = acc[mapping.article]
                rank = _STATUS_RANK.get(mapping.status, -1)
                if mapping.status == "not_applicable":
                    if entry["rank"] == -1:
                        entry["rank"] = rank
                        entry["evidence"] = mapping.evidence
                        entry["reason"] = mapping.reason
                elif rank > entry["rank"]:
                    entry["rank"] = rank
                    entry["evidence"] = mapping.evidence
                if mapping.proof_ids:
                    entry["proof_ids"].extend(mapping.proof_ids)

        _RANK_TO_STATUS = {v: k for k, v in _STATUS_RANK.items()}
        articles = []
        gaps = []
        summary = {"covered": 0, "partial": 0, "gap": 0, "not_applicable": 0}

        for crit, title in _SOC2_CRITERIA:
            entry = acc[crit]
            rank = entry["rank"]
            if rank == -1:
                if crit == "A1.1":
                    status = "not_applicable"
                    evidence = "Infrastructure obligation — not verifiable from transaction proofs"
                else:
                    status = "gap"
                    evidence = "No proofs analyzed in the selected date range"
            else:
                status = _RANK_TO_STATUS[rank]
                evidence = entry["evidence"]

            am = ArticleMapping(
                article=crit,
                title=title,
                status=status,
                evidence=evidence,
                proof_ids=list(dict.fromkeys(entry["proof_ids"]))[:10],
                reason=entry.get("reason"),
            )
            articles.append(am)
            summary[status] = summary.get(status, 0) + 1
            if status == "gap":
                gaps.append(f"{crit}: {title}")

        return ComplianceReport(
            report_id=generate_report_id(),
            framework=self.name,
            framework_version=self.version,
            date_range=date_range,
            proof_count=proofs_loaded,
            articles=articles,
            gaps=gaps,
            summary=summary,
            coverage_since=coverage_since,
        )


register_framework(SOC2ReadinessFramework())
