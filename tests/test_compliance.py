"""Tests for EU AI Act compliance report generation."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proof(proof_id, parties=None, tsa_ok=True, timestamp="2026-01-15T12:00:00+00:00"):
    """Build a minimal valid proof dict for testing."""
    p = {
        "proof_id": proof_id,
        "spec_version": "1.2",
        "hashes": {
            "request": "sha256:aabbcc",
            "response": "sha256:ddeeff",
            "chain": "sha256:112233",
        },
        "parties": parties or {
            "buyer_fingerprint": "fp_test_abc",
            "seller": "example.com",
            "agent_identity": "did:key:z6Mk...",
            "agent_identity_verified": True,
            "agent_version": "1.0.0",
        },
        "certification_fee": {"transaction_id": "pi_test_123"},
        "timestamp": timestamp,
        "timestamp_authority": {
            "status": "verified" if tsa_ok else "failed",
            "provider": "freetsa.org",
        },
    }
    return p


# ---------------------------------------------------------------------------
# Unit tests — EUAIActFramework.map_proof
# ---------------------------------------------------------------------------

def test_map_proof_fully_covered():
    from trust_layer.compliance import EUAIActFramework
    fw = EUAIActFramework()
    proof = _make_proof("prf_001")

    mappings = fw.map_proof(proof)
    by_article = {m.article: m for m in mappings}

    assert by_article["Art. 9"].status == "covered"
    assert by_article["Art. 10"].status == "not_applicable"
    assert by_article["Art. 13"].status == "covered"
    assert by_article["Art. 14"].status == "covered"
    assert by_article["Art. 22"].status == "covered"


def test_map_proof_no_agent_identity():
    from trust_layer.compliance import EUAIActFramework
    fw = EUAIActFramework()
    proof = _make_proof("prf_002", parties={
        "buyer_fingerprint": "fp_test",
        "seller": "example.com",
        "agent_identity": None,
        "agent_identity_verified": False,
        "agent_version": None,
    })
    mappings = fw.map_proof(proof)
    by_article = {m.article: m for m in mappings}

    assert by_article["Art. 13"].status == "partial"
    assert by_article["Art. 14"].status == "partial"


def test_map_proof_no_parties():
    from trust_layer.compliance import EUAIActFramework
    fw = EUAIActFramework()
    # No parties AND no verified TSA → Art. 13 gap, Art. 14 gap
    proof = _make_proof("prf_003", parties={
        "buyer_fingerprint": "",
        "seller": "",
        "agent_identity": None,
        "agent_identity_verified": False,
        "agent_version": None,
    }, tsa_ok=False)
    mappings = fw.map_proof(proof)
    by_article = {m.article: m for m in mappings}

    assert by_article["Art. 13"].status == "gap"
    assert by_article["Art. 14"].status == "gap"


def test_art10_always_not_applicable():
    from trust_layer.compliance import EUAIActFramework
    fw = EUAIActFramework()
    for parties in [None, {"buyer_fingerprint": "", "seller": "", "agent_identity": None, "agent_identity_verified": False, "agent_version": None}]:
        proof = _make_proof("prf_na", parties=parties)
        mappings = fw.map_proof(proof)
        by_article = {m.article: m for m in mappings}
        assert by_article["Art. 10"].status == "not_applicable"


# ---------------------------------------------------------------------------
# Unit tests — generate_report aggregation
# ---------------------------------------------------------------------------

def test_generate_report_empty_proof_ids():
    from trust_layer.compliance import EUAIActFramework
    fw = EUAIActFramework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-03-31"})

    assert report.proof_count == 0
    assert report.framework == "eu_ai_act"
    by_article = {a.article: a for a in report.articles}
    assert by_article["Art. 10"].status == "not_applicable"
    # No proofs → all others should be gap
    assert by_article["Art. 9"].status == "gap"


def test_generate_report_with_proofs(tmp_path, monkeypatch):
    import trust_layer.proofs as proofs_mod
    monkeypatch.setattr(proofs_mod, "PROOFS_DIR", tmp_path / "proofs")
    (tmp_path / "proofs").mkdir(exist_ok=True)

    from trust_layer.compliance import EUAIActFramework
    from trust_layer.proofs import store_proof

    proof1 = _make_proof("prf_20260115_000000_aaa111")
    proof2 = _make_proof("prf_20260116_000000_bbb222")
    store_proof(proof1["proof_id"], proof1)
    store_proof(proof2["proof_id"], proof2)

    fw = EUAIActFramework()
    report = fw.generate_report(
        [proof1["proof_id"], proof2["proof_id"]],
        {"from": "2026-01-15", "to": "2026-01-17"},
    )

    assert report.proof_count == 2
    by_article = {a.article: a for a in report.articles}
    assert by_article["Art. 9"].status == "covered"
    assert by_article["Art. 22"].status == "covered"
    assert "Art. 10" not in report.gaps


def test_report_summary_counts():
    from trust_layer.compliance import EUAIActFramework
    fw = EUAIActFramework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-01-31"})

    total = sum(report.summary.values())
    assert total == 6  # 6 articles total


# ---------------------------------------------------------------------------
# Integration tests — POST /v1/compliance-report endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def compliance_client():
    from trust_layer.app import app
    return TestClient(app)


def test_compliance_missing_api_key(compliance_client):
    resp = compliance_client.post("/v1/compliance-report", json={
        "framework": "eu_ai_act", "date_from": "2026-01-01", "date_to": "2026-03-31"
    })
    assert resp.status_code == 401


def test_compliance_invalid_api_key(compliance_client):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "eu_ai_act", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": "invalid_key_xyz"},
    )
    assert resp.status_code == 401


def test_compliance_unknown_framework(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "nonexistent_xyz", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400
    assert "unknown_framework" in resp.json()["error"]["code"]


def test_compliance_missing_date_from(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "eu_ai_act", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400


def test_compliance_invalid_date(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "eu_ai_act", "date_from": "not-a-date", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400


def test_compliance_date_range_inverted(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "eu_ai_act", "date_from": "2026-03-31", "date_to": "2026-01-01"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400
    assert "invalid_range" in resp.json()["error"]["code"]


def test_compliance_success_no_proofs(compliance_client, test_api_key):
    """Success even with zero proofs in range — returns empty report."""
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "eu_ai_act", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "eu_ai_act"
    assert data["framework_version"] == "1.0"
    assert data["proof_count"] == 0
    assert isinstance(data["articles"], list)
    assert len(data["articles"]) == 6
    assert isinstance(data["summary"], dict)
    assert data["report_id"].startswith("rpt_")


def test_compliance_response_structure(compliance_client, test_api_key):
    """Verify all expected fields are present in a successful response."""
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "eu_ai_act", "date_from": "2026-01-01", "date_to": "2026-12-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()

    required_fields = {"report_id", "framework", "framework_version", "date_range",
                       "proof_count", "articles", "gaps", "summary"}
    assert required_fields.issubset(data.keys())

    # Each article must have required keys
    for article in data["articles"]:
        for key in ("article", "title", "status", "evidence"):
            assert key in article, f"Missing key '{key}' in article {article}"

    # Summary values must be non-negative integers
    for k, v in data["summary"].items():
        assert isinstance(v, int) and v >= 0

    # Art. 10 must always be not_applicable
    art10 = next(a for a in data["articles"] if a["article"] == "Art. 10")
    assert art10["status"] == "not_applicable"


# ---------------------------------------------------------------------------
# Unit tests — ISO42001Framework.map_proof
# ---------------------------------------------------------------------------

def test_iso42001_map_proof_all_present_fields():
    """Test proof with all fields present — verifiable except integrity (fake hashes in fixture).

    § 8.2 is 'partial' (not 'covered') because the fixture uses a fake chain hash
    that does not pass verify_proof_integrity — same constraint as EU AI Act Art. 17.
    § 9.2 is 'gap' for the same reason.
    """
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_001")

    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 6.1"].status == "covered"   # chain hash present
    assert by_clause["§ 8.2"].status == "partial"    # chain present but fake hash fails integrity
    assert by_clause["§ 8.4"].status == "covered"    # spec_version + agent_version both present
    assert by_clause["§ 9.1"].status == "covered"    # TSA verified
    assert by_clause["§ 10.1"].status == "not_applicable"


def test_iso42001_returns_6_clauses():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    mappings = fw.map_proof(_make_proof("prf_iso_count"))
    assert len(mappings) == 6


def test_iso42001_clause_10_1_always_not_applicable():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    for parties in [
        None,
        {"buyer_fingerprint": "", "seller": "", "agent_identity": None,
         "agent_identity_verified": False, "agent_version": None},
    ]:
        mappings = fw.map_proof(_make_proof("prf_iso_na", parties=parties))
        by_clause = {m.article: m for m in mappings}
        assert by_clause["§ 10.1"].status == "not_applicable"
        assert by_clause["§ 10.1"].reason is not None


def test_iso42001_no_chain_hash():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_002")
    proof["hashes"].pop("chain")

    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 6.1"].status == "gap"
    assert by_clause["§ 8.2"].status == "gap"
    assert by_clause["§ 9.2"].status == "gap"


def test_iso42001_no_agent_version():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_003", parties={
        "buyer_fingerprint": "fp_test",
        "seller": "example.com",
        "agent_identity": "did:key:z6Mk...",
        "agent_identity_verified": True,
        "agent_version": None,
    })
    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 8.4"].status == "partial"
    assert "agent_version" in by_clause["§ 8.4"].evidence


def test_iso42001_no_spec_version():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_004")
    proof.pop("spec_version", None)

    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 8.4"].status == "partial"
    assert "spec_version" in by_clause["§ 8.4"].evidence


def test_iso42001_no_versions_at_all():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_005", parties={
        "buyer_fingerprint": "fp_test",
        "seller": "example.com",
        "agent_identity": "did:key:z6Mk...",
        "agent_identity_verified": True,
        "agent_version": None,
    })
    proof.pop("spec_version", None)

    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 8.4"].status == "gap"


def test_iso42001_tsa_failed_but_timestamp_present():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_006", tsa_ok=False)

    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 9.1"].status == "partial"


def test_iso42001_no_timestamp():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    proof = _make_proof("prf_iso_007", tsa_ok=False)
    proof.pop("timestamp", None)

    mappings = fw.map_proof(proof)
    by_clause = {m.article: m for m in mappings}

    assert by_clause["§ 9.1"].status == "gap"


# ---------------------------------------------------------------------------
# Unit tests — ISO42001Framework.generate_report
# ---------------------------------------------------------------------------

def test_iso42001_generate_report_empty():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-03-31"})

    assert report.proof_count == 0
    assert report.framework == "iso_42001"
    assert report.framework_version == "1.0"

    by_clause = {a.article: a for a in report.articles}
    assert by_clause["§ 10.1"].status == "not_applicable"
    assert by_clause["§ 6.1"].status == "gap"
    assert by_clause["§ 9.2"].status == "gap"


def test_iso42001_generate_report_summary_counts():
    from trust_layer.compliance import ISO42001Framework
    fw = ISO42001Framework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-01-31"})

    total = sum(report.summary.values())
    assert total == 6  # 6 clauses total


def test_iso42001_generate_report_with_proofs(tmp_path, monkeypatch):
    import trust_layer.proofs as proofs_mod
    monkeypatch.setattr(proofs_mod, "PROOFS_DIR", tmp_path / "proofs")
    (tmp_path / "proofs").mkdir(exist_ok=True)

    from trust_layer.compliance import ISO42001Framework
    from trust_layer.proofs import store_proof

    proof1 = _make_proof("prf_iso_20260115_000000_aaa111")
    proof2 = _make_proof("prf_iso_20260116_000000_bbb222")
    store_proof(proof1["proof_id"], proof1)
    store_proof(proof2["proof_id"], proof2)

    fw = ISO42001Framework()
    report = fw.generate_report(
        [proof1["proof_id"], proof2["proof_id"]],
        {"from": "2026-01-15", "to": "2026-01-17"},
    )

    assert report.proof_count == 2
    by_clause = {a.article: a for a in report.articles}
    assert by_clause["§ 6.1"].status == "covered"   # chain hash present
    assert by_clause["§ 9.1"].status == "covered"   # TSA verified
    # § 9.2 is 'gap' — fixture proofs use fake hashes that don't pass integrity check
    assert by_clause["§ 9.2"].status == "gap"
    assert "§ 10.1" not in report.gaps


def test_iso42001_framework_registered():
    from trust_layer.compliance import get_framework, list_frameworks
    assert "iso_42001" in list_frameworks()
    fw = get_framework("iso_42001")
    assert fw is not None
    assert fw.name == "iso_42001"
    assert fw.version == "1.0"


# ---------------------------------------------------------------------------
# Integration tests — POST /v1/compliance-report with iso_42001
# ---------------------------------------------------------------------------

def test_iso42001_endpoint_success_no_proofs(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "iso_42001", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "iso_42001"
    assert data["framework_version"] == "1.0"
    assert data["proof_count"] == 0
    assert len(data["articles"]) == 6
    assert data["report_id"].startswith("rpt_")


def test_iso42001_endpoint_response_structure(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "iso_42001", "date_from": "2026-01-01", "date_to": "2026-12-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()

    required_fields = {"report_id", "framework", "framework_version", "date_range",
                       "proof_count", "articles", "gaps", "summary"}
    assert required_fields.issubset(data.keys())

    for article in data["articles"]:
        for key in ("article", "title", "status", "evidence"):
            assert key in article, f"Missing key '{key}' in article {article}"

    for k, v in data["summary"].items():
        assert isinstance(v, int) and v >= 0


def test_iso42001_endpoint_10_1_not_applicable(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "iso_42001", "date_from": "2026-01-01", "date_to": "2026-12-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    clause_10_1 = next(a for a in data["articles"] if a["article"] == "§ 10.1")
    assert clause_10_1["status"] == "not_applicable"


def test_iso42001_listed_in_available_frameworks(compliance_client, test_api_key):
    """Unknown framework error message lists iso_42001 as available."""
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "nonexistent_xyz", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400
    msg = resp.json()["error"]["message"]
    assert "iso_42001" in msg


def test_default_framework_still_eu_ai_act(compliance_client, test_api_key):
    """Omitting 'framework' defaults to eu_ai_act — not changed by adding iso_42001."""
    resp = compliance_client.post("/v1/compliance-report",
        json={"date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    assert resp.json()["framework"] == "eu_ai_act"


# ---------------------------------------------------------------------------
# Unit tests — NISTAIRMFFramework.map_proof
# ---------------------------------------------------------------------------

def test_nist_map_proof_all_present():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    proof = _make_proof("prf_nist_001")
    mappings = fw.map_proof(proof)
    by_sub = {m.article: m for m in mappings}

    assert by_sub["GOVERN 1.1"].status == "not_applicable"
    assert by_sub["MAP 1.1"].status == "covered"      # spec_version + agent_identity
    assert by_sub["MAP 5.2"].status == "covered"      # chain hash present
    assert by_sub["MEASURE 2.5"].status == "covered"  # TSA verified
    assert by_sub["MANAGE 4.1"].status == "covered"   # proof_id + timestamp


def test_nist_returns_7_subcategories():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    assert len(fw.map_proof(_make_proof("prf_nist_count"))) == 7


def test_nist_govern_1_1_always_not_applicable():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    for parties in [None, {"buyer_fingerprint": "", "seller": "", "agent_identity": None,
                           "agent_identity_verified": False, "agent_version": None}]:
        by_sub = {m.article: m for m in fw.map_proof(_make_proof("prf_nist_na", parties=parties))}
        assert by_sub["GOVERN 1.1"].status == "not_applicable"
        assert by_sub["GOVERN 1.1"].reason is not None


def test_nist_map_1_1_partial_no_agent_identity():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    proof = _make_proof("prf_nist_002", parties={
        "buyer_fingerprint": "fp_test", "seller": "example.com",
        "agent_identity": None, "agent_identity_verified": False, "agent_version": "1.0",
    })
    by_sub = {m.article: m for m in fw.map_proof(proof)}
    assert by_sub["MAP 1.1"].status == "partial"
    assert "agent_identity" in by_sub["MAP 1.1"].evidence


def test_nist_map_1_1_gap_no_context():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    proof = _make_proof("prf_nist_003", parties={
        "buyer_fingerprint": "fp_test", "seller": "example.com",
        "agent_identity": None, "agent_identity_verified": False, "agent_version": None,
    })
    proof.pop("spec_version", None)
    by_sub = {m.article: m for m in fw.map_proof(proof)}
    assert by_sub["MAP 1.1"].status == "gap"


def test_nist_map_5_2_gap_no_chain():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    proof = _make_proof("prf_nist_004")
    proof["hashes"].pop("chain")
    by_sub = {m.article: m for m in fw.map_proof(proof)}
    assert by_sub["MAP 5.2"].status == "gap"
    assert by_sub["MANAGE 1.3"].status == "gap"


def test_nist_measure_2_5_partial_no_tsa():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    by_sub = {m.article: m for m in fw.map_proof(_make_proof("prf_nist_005", tsa_ok=False))}
    assert by_sub["MEASURE 2.5"].status == "partial"


def test_nist_generate_report_empty():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-03-31"})
    assert report.framework == "nist_ai_rmf"
    assert report.framework_version == "1.0"
    assert report.proof_count == 0
    by_sub = {a.article: a for a in report.articles}
    assert by_sub["GOVERN 1.1"].status == "not_applicable"
    assert by_sub["MAP 5.2"].status == "gap"


def test_nist_generate_report_summary_counts():
    from trust_layer.compliance import NISTAIRMFFramework
    fw = NISTAIRMFFramework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-01-31"})
    assert sum(report.summary.values()) == 7


def test_nist_framework_registered():
    from trust_layer.compliance import get_framework, list_frameworks
    assert "nist_ai_rmf" in list_frameworks()
    fw = get_framework("nist_ai_rmf")
    assert fw is not None and fw.name == "nist_ai_rmf"


def test_nist_endpoint_success(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "nist_ai_rmf", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "nist_ai_rmf"
    assert len(data["articles"]) == 7
    assert data["report_id"].startswith("rpt_")


def test_nist_endpoint_govern_not_applicable(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "nist_ai_rmf", "date_from": "2026-01-01", "date_to": "2026-12-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    govern = next(a for a in resp.json()["articles"] if a["article"] == "GOVERN 1.1")
    assert govern["status"] == "not_applicable"


def test_nist_listed_in_available_frameworks(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "bad_fw", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert "nist_ai_rmf" in resp.json()["error"]["message"]


# ---------------------------------------------------------------------------
# Unit tests — SOC2ReadinessFramework.map_proof
# ---------------------------------------------------------------------------

def test_soc2_map_proof_all_present():
    """Test proof with all fields present.

    PI1.1 is 'partial' (not 'covered') — fixture uses fake hashes that fail verify_proof_integrity.
    PI1.2 is 'partial' — fixture certification_fee has no 'status' field (same constraint).
    """
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    proof = _make_proof("prf_soc2_001")
    by_crit = {m.article: m for m in fw.map_proof(proof)}

    assert by_crit["CC6.1"].status == "covered"        # buyer_fingerprint + seller
    assert by_crit["CC6.7"].status == "covered"        # all 3 hashes present
    assert by_crit["CC7.2"].status == "covered"        # TSA verified
    assert by_crit["PI1.1"].status == "partial"        # chain present but fake hash fails integrity
    assert by_crit["PI1.2"].status == "partial"        # fixture fee has no status field
    assert by_crit["A1.1"].status == "not_applicable"


def test_soc2_returns_6_criteria():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    assert len(fw.map_proof(_make_proof("prf_soc2_count"))) == 6


def test_soc2_a1_1_always_not_applicable():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    for parties in [None, {"buyer_fingerprint": "", "seller": "",
                           "agent_identity": None, "agent_identity_verified": False,
                           "agent_version": None}]:
        by_crit = {m.article: m for m in fw.map_proof(_make_proof("prf_soc2_na", parties=parties))}
        assert by_crit["A1.1"].status == "not_applicable"
        assert by_crit["A1.1"].reason is not None


def test_soc2_cc6_1_partial_no_seller():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    proof = _make_proof("prf_soc2_002", parties={
        "buyer_fingerprint": "fp_test", "seller": "",
        "agent_identity": "did:key:z6Mk...", "agent_identity_verified": True, "agent_version": "1.0",
    })
    by_crit = {m.article: m for m in fw.map_proof(proof)}
    assert by_crit["CC6.1"].status == "partial"
    assert "seller" in by_crit["CC6.1"].evidence


def test_soc2_cc6_7_partial_missing_response_hash():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    proof = _make_proof("prf_soc2_003")
    proof["hashes"].pop("response")
    by_crit = {m.article: m for m in fw.map_proof(proof)}
    assert by_crit["CC6.7"].status == "partial"


def test_soc2_cc7_2_partial_no_tsa():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    by_crit = {m.article: m for m in fw.map_proof(_make_proof("prf_soc2_004", tsa_ok=False))}
    assert by_crit["CC7.2"].status == "partial"


def test_soc2_pi1_2_partial_no_fee():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    proof = _make_proof("prf_soc2_005")
    proof["certification_fee"]["status"] = "pending"
    by_crit = {m.article: m for m in fw.map_proof(proof)}
    assert by_crit["PI1.2"].status == "partial"


def test_soc2_generate_report_empty():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-03-31"})
    assert report.framework == "soc2_readiness"
    assert report.framework_version == "1.0"
    assert report.proof_count == 0
    by_crit = {a.article: a for a in report.articles}
    assert by_crit["A1.1"].status == "not_applicable"
    assert by_crit["CC6.1"].status == "gap"


def test_soc2_generate_report_summary_counts():
    from trust_layer.compliance import SOC2ReadinessFramework
    fw = SOC2ReadinessFramework()
    report = fw.generate_report([], {"from": "2026-01-01", "to": "2026-01-31"})
    assert sum(report.summary.values()) == 6


def test_soc2_framework_registered():
    from trust_layer.compliance import get_framework, list_frameworks
    assert "soc2_readiness" in list_frameworks()
    fw = get_framework("soc2_readiness")
    assert fw is not None and fw.name == "soc2_readiness"


def test_soc2_endpoint_success(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "soc2_readiness", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["framework"] == "soc2_readiness"
    assert len(data["articles"]) == 6
    assert data["report_id"].startswith("rpt_")


def test_soc2_endpoint_a1_1_not_applicable(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "soc2_readiness", "date_from": "2026-01-01", "date_to": "2026-12-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    a1_1 = next(a for a in resp.json()["articles"] if a["article"] == "A1.1")
    assert a1_1["status"] == "not_applicable"


def test_soc2_listed_in_available_frameworks(compliance_client, test_api_key):
    resp = compliance_client.post("/v1/compliance-report",
        json={"framework": "bad_fw", "date_from": "2026-01-01", "date_to": "2026-03-31"},
        headers={"X-Api-Key": test_api_key},
    )
    assert "soc2_readiness" in resp.json()["error"]["message"]


def test_soc2_disclaimer_in_docstring():
    """Verify the SOC 2 readiness disclaimer exists in the framework class."""
    from trust_layer.compliance import SOC2ReadinessFramework
    assert "readiness evidence" in SOC2ReadinessFramework.__doc__
    assert "CPA" in SOC2ReadinessFramework.__doc__
