"""Tests for MCP security posture assessment."""

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Unit tests — analyzers
# ---------------------------------------------------------------------------

def test_permission_analyzer_no_findings():
    from trust_layer.mcp_assess import PermissionAnalyzer
    analyzer = PermissionAnalyzer()
    tools = [{"name": "get_weather", "description": "Retrieve current weather data"}]
    findings = analyzer.analyze(tools, baseline=None)
    assert findings == []


def test_permission_analyzer_code_execution():
    from trust_layer.mcp_assess import PermissionAnalyzer, Finding
    analyzer = PermissionAnalyzer()
    tools = [{"name": "run_script", "description": "Execute a shell command"}]
    findings = analyzer.analyze(tools, baseline=None)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].tool == "run_script"


def test_permission_analyzer_filesystem_write():
    from trust_layer.mcp_assess import PermissionAnalyzer
    analyzer = PermissionAnalyzer()
    tools = [{"name": "write_file", "description": "Write content to disk"}]
    findings = analyzer.analyze(tools, baseline=None)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_permission_analyzer_network_access():
    from trust_layer.mcp_assess import PermissionAnalyzer
    analyzer = PermissionAnalyzer()
    tools = [{"name": "fetch_url", "description": "Send an HTTP request to a URL"}]
    findings = analyzer.analyze(tools, baseline=None)
    assert any(f.severity == "medium" for f in findings)


def test_drift_analyzer_no_baseline():
    from trust_layer.mcp_assess import DescriptionDriftAnalyzer
    analyzer = DescriptionDriftAnalyzer()
    tools = [{"name": "echo", "description": "Echo input"}]
    findings = analyzer.analyze(tools, baseline=None)
    assert findings == []


def test_drift_analyzer_new_tool():
    from trust_layer.mcp_assess import DescriptionDriftAnalyzer
    analyzer = DescriptionDriftAnalyzer()
    baseline = {"tools": [{"name": "echo", "description": "Echo input"}]}
    tools = [
        {"name": "echo", "description": "Echo input"},
        {"name": "new_tool", "description": "A new tool"},
    ]
    findings = analyzer.analyze(tools, baseline=baseline)
    names = [f.tool for f in findings]
    assert "new_tool" in names


def test_drift_analyzer_removed_tool():
    from trust_layer.mcp_assess import DescriptionDriftAnalyzer
    analyzer = DescriptionDriftAnalyzer()
    baseline = {"tools": [
        {"name": "echo", "description": "Echo input"},
        {"name": "old_tool", "description": "Old tool"},
    ]}
    tools = [{"name": "echo", "description": "Echo input"}]
    findings = analyzer.analyze(tools, baseline=baseline)
    names = [f.tool for f in findings]
    assert "old_tool" in names


def test_drift_analyzer_changed_description():
    from trust_layer.mcp_assess import DescriptionDriftAnalyzer
    analyzer = DescriptionDriftAnalyzer()
    baseline = {"tools": [{"name": "echo", "description": "Echo input safely"}]}
    tools = [{"name": "echo", "description": "Execute arbitrary code"}]
    findings = analyzer.analyze(tools, baseline=baseline)
    assert any(f.tool == "echo" and "changed" in f.message.lower() for f in findings)


def test_version_analyzer_no_change():
    from trust_layer.mcp_assess import VersionTrackingAnalyzer
    analyzer = VersionTrackingAnalyzer()
    baseline = {"server_version": "1.2.0", "_current_server_version": "1.2.1"}
    findings = analyzer.analyze([], baseline=baseline)
    assert findings == []


def test_version_analyzer_downgrade():
    from trust_layer.mcp_assess import VersionTrackingAnalyzer
    analyzer = VersionTrackingAnalyzer()
    baseline = {"server_version": "2.0.0", "_current_server_version": "1.9.0"}
    findings = analyzer.analyze([], baseline=baseline)
    assert any("downgrade" in f.message.lower() for f in findings)
    assert findings[0].severity == "high"


def test_version_analyzer_major_bump():
    from trust_layer.mcp_assess import VersionTrackingAnalyzer
    analyzer = VersionTrackingAnalyzer()
    baseline = {"server_version": "1.0.0", "_current_server_version": "2.0.0"}
    findings = analyzer.analyze([], baseline=baseline)
    assert any("major" in f.message.lower() for f in findings)
    assert findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# Unit tests — baseline I/O
# ---------------------------------------------------------------------------

def test_save_and_load_baseline(tmp_path, monkeypatch):
    import trust_layer.mcp_assess as m
    monkeypatch.setattr(m, "MCP_BASELINES_DIR", tmp_path / "baselines")
    (tmp_path / "baselines").mkdir()

    data = {"tools": [{"name": "echo", "description": "Echo"}], "server_version": "1.0.0"}
    m.save_baseline("fp_abc123", "my-server", data)
    loaded = m.load_baseline("fp_abc123", "my-server")
    assert loaded == data


def test_load_nonexistent_baseline(tmp_path, monkeypatch):
    import trust_layer.mcp_assess as m
    monkeypatch.setattr(m, "MCP_BASELINES_DIR", tmp_path / "baselines")
    (tmp_path / "baselines").mkdir()

    result = m.load_baseline("fp_nobody", "no-server")
    assert result is None


def test_server_id_sanitization(tmp_path, monkeypatch):
    import trust_layer.mcp_assess as m
    monkeypatch.setattr(m, "MCP_BASELINES_DIR", tmp_path / "baselines")
    (tmp_path / "baselines").mkdir()

    # Path traversal attempt — should be sanitized
    data = {"tools": []}
    m.save_baseline("fp_abc123", "../../../etc/passwd", data)
    loaded = m.load_baseline("fp_abc123", "../../../etc/passwd")
    assert loaded == data

    # Verify file is actually inside baselines dir
    saved_path = m._baseline_path("fp_abc123", "../../../etc/passwd")
    assert tmp_path in saved_path.parents


# ---------------------------------------------------------------------------
# Unit tests — build_assessment
# ---------------------------------------------------------------------------

def test_build_assessment_first_call(tmp_path, monkeypatch):
    import trust_layer.mcp_assess as m
    monkeypatch.setattr(m, "MCP_BASELINES_DIR", tmp_path / "baselines")
    monkeypatch.setattr(m, "ASSESSMENTS_DIR", tmp_path / "assessments")
    (tmp_path / "baselines").mkdir()
    (tmp_path / "assessments").mkdir()

    tools = [{"name": "echo", "description": "Echo input"}]
    result = m.build_assessment("fp_abc", "test-server", tools, "1.0.0")

    assert result["assess_id"].startswith("asr_")
    assert result["baseline_status"] == "created"
    assert result["drift_detected"] is False
    assert isinstance(result["risk_score"], int)
    assert 0 <= result["risk_score"] <= 100


def test_build_assessment_drift_detection(tmp_path, monkeypatch):
    import trust_layer.mcp_assess as m
    monkeypatch.setattr(m, "MCP_BASELINES_DIR", tmp_path / "baselines")
    monkeypatch.setattr(m, "ASSESSMENTS_DIR", tmp_path / "assessments")
    (tmp_path / "baselines").mkdir()
    (tmp_path / "assessments").mkdir()

    tools_v1 = [{"name": "echo", "description": "Echo input"}]
    m.build_assessment("fp_abc", "test-server", tools_v1, "1.0.0")

    tools_v2 = [
        {"name": "echo", "description": "Echo input"},
        {"name": "exec", "description": "Run shell command"},
    ]
    result = m.build_assessment("fp_abc", "test-server", tools_v2, "1.0.1")
    assert result["baseline_status"] == "updated"
    assert result["drift_detected"] is True
    assert "exec" in result["drift_summary"]["new_tools"]


# ---------------------------------------------------------------------------
# Integration tests — POST /v1/assess endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def assess_client():
    from trust_layer.app import app
    return TestClient(app)


def test_assess_missing_api_key(assess_client):
    resp = assess_client.post("/v1/assess", json={
        "server_id": "test", "manifest": {"tools": [{"name": "echo", "description": "x"}]}
    })
    assert resp.status_code == 401


def test_assess_invalid_api_key(assess_client):
    resp = assess_client.post("/v1/assess",
        json={"server_id": "test", "manifest": {"tools": [{"name": "echo", "description": "x"}]}},
        headers={"X-Api-Key": "invalid_key_xyz"},
    )
    assert resp.status_code == 401


def test_assess_missing_server_id(assess_client, test_api_key):
    resp = assess_client.post("/v1/assess",
        json={"manifest": {"tools": [{"name": "echo", "description": "x"}]}},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400
    assert "server_id" in resp.json()["error"]["message"]


def test_assess_missing_manifest(assess_client, test_api_key):
    resp = assess_client.post("/v1/assess",
        json={"server_id": "test"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400


def test_assess_empty_tools(assess_client, test_api_key):
    resp = assess_client.post("/v1/assess",
        json={"server_id": "test", "manifest": {"tools": []}},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400


def test_assess_success(assess_client, test_api_key):
    resp = assess_client.post("/v1/assess",
        json={
            "server_id": "smoke-server",
            "manifest": {
                "tools": [
                    {"name": "get_weather", "description": "Retrieve weather data"},
                    {"name": "read_file", "description": "Read a file from disk"},
                ]
            },
            "server_version": "1.0.0",
        },
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["assess_id"].startswith("asr_")
    assert data["server_id"] == "smoke-server"
    assert data["baseline_status"] == "created"
    assert isinstance(data["risk_score"], int)
    assert isinstance(data["findings"], list)
    assert isinstance(data["drift_detected"], bool)


def test_assess_drift_second_call(assess_client, test_api_key):
    """Second call with new tool detects drift."""
    base = {
        "server_id": "drift-server",
        "manifest": {"tools": [{"name": "echo", "description": "Echo input"}]},
        "server_version": "1.0.0",
    }
    assess_client.post("/v1/assess", json=base, headers={"X-Api-Key": test_api_key})

    resp = assess_client.post("/v1/assess",
        json={
            "server_id": "drift-server",
            "manifest": {
                "tools": [
                    {"name": "echo", "description": "Echo input"},
                    {"name": "shell_exec", "description": "Run shell commands"},
                ]
            },
            "server_version": "1.0.1",
        },
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["drift_detected"] is True
    assert data["baseline_status"] == "updated"
