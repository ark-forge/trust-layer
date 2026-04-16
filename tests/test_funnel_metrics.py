"""Tests for funnel metrics instrumentation (cta_impression, register_page_visit, register_completion)."""

import json
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from trust_layer.app import app
    return TestClient(app)


@pytest.fixture
def internal_key(tmp_path):
    from trust_layer.keys import create_api_key
    key = create_api_key("", "internal_test", "internal@arkforge.tech", test_mode=False, plan="internal")
    return key


@pytest.fixture
def free_key(tmp_path):
    from trust_layer.keys import create_api_key
    key = create_api_key("", "free_test", "free@test.com", test_mode=False, plan="free")
    return key


def _read_funnel_events(tmp_path) -> list:
    log = tmp_path / "data" / "funnel_events.jsonl"
    if not log.exists():
        return []
    events = []
    for line in log.read_text().splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


class TestCtaImpression:
    def test_assess_logs_cta_impression(self, client, free_key, tmp_path):
        resp = client.post(
            "/v1/assess",
            json={"server_id": "test-mcp", "manifest": {"tools": [{"name": "t1"}]}},
            headers={"X-Api-Key": free_key},
        )
        assert resp.status_code == 200
        events = _read_funnel_events(tmp_path)
        cta_events = [e for e in events if e["event"] == "cta_impression"]
        assert len(cta_events) == 1
        assert cta_events[0]["server_id"] == "test-mcp"
        assert cta_events[0]["assess_id"].startswith("asr_")


class TestRegisterPageVisit:
    def test_register_get_logs_visit(self, client, tmp_path):
        resp = client.get("/register?scan_id=asr_20260416_120000_abc123")
        assert resp.status_code == 200
        events = _read_funnel_events(tmp_path)
        visit_events = [e for e in events if e["event"] == "register_page_visit"]
        assert len(visit_events) == 1
        assert visit_events[0]["scan_id"] == "asr_20260416_120000_abc123"[:32]

    def test_register_get_without_scan_id(self, client, tmp_path):
        resp = client.get("/register")
        assert resp.status_code == 200
        events = _read_funnel_events(tmp_path)
        visit_events = [e for e in events if e["event"] == "register_page_visit"]
        assert len(visit_events) == 1
        assert visit_events[0]["scan_id"] == ""


class TestRegisterCompletion:
    def test_register_post_logs_completion(self, client, tmp_path):
        resp = client.post(
            "/api/register",
            json={"email": "newuser@example.com", "source": "web_register", "scan_id": "asr_test_123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "api_key" in data

        events = _read_funnel_events(tmp_path)
        completion_events = [e for e in events if e["event"] == "register_completion"]
        assert len(completion_events) == 1
        assert completion_events[0]["source"] == "web_register"
        assert completion_events[0]["scan_id"] == "asr_test_123"

    def test_existing_key_no_completion_event(self, client, tmp_path):
        client.post("/api/register", json={"email": "dup@example.com", "source": "web_register"})
        events_before = len(_read_funnel_events(tmp_path))

        resp = client.post("/api/register", json={"email": "dup@example.com", "source": "web_register"})
        assert resp.status_code == 200
        assert resp.json().get("already_existed") is True

        events_after = _read_funnel_events(tmp_path)
        completions_after = [e for e in events_after if e["event"] == "register_completion"]
        assert len(completions_after) == 1


class TestFunnelMetricsEndpoint:
    def test_requires_internal_key(self, client, free_key):
        resp = client.get("/v1/funnel-metrics", headers={"X-Api-Key": free_key})
        assert resp.status_code == 403

    def test_returns_aggregated_counts(self, client, internal_key, free_key, tmp_path):
        client.post(
            "/v1/assess",
            json={"server_id": "s1", "manifest": {"tools": [{"name": "t1"}]}},
            headers={"X-Api-Key": free_key},
        )
        client.get("/register?scan_id=asr_test")
        client.post("/api/register", json={"email": "agg@example.com", "source": "web_register"})

        resp = client.get("/v1/funnel-metrics", headers={"X-Api-Key": internal_key})
        assert resp.status_code == 200
        data = resp.json()
        assert data["cta_impressions"] >= 1
        assert data["register_page_visits"] >= 1
        assert data["register_completions"] >= 1
        assert data["cta_to_visit_rate"] is not None
        assert data["visit_to_completion_rate"] is not None
        assert "by_day" in data
