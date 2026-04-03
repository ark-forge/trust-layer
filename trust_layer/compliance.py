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
