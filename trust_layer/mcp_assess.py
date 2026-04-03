"""MCP server security posture assessment.

Pluggable analyzer architecture mirrors receipt.py:
- BaseAnalyzer (ABC) + registry + register_analyzer()
- Three built-in analyzers: Permission, DescriptionDrift, VersionTracking
- Baseline storage per (fingerprint, server_id) in data/mcp_baselines/
- Assessment artifact: asr_YYYYMMDD_HHMMSS_6hex

To add a new analyzer:
1. Subclass BaseAnalyzer
2. Set `name`
3. Implement `analyze(tools, baseline) -> list[Finding]`
4. Call `register_analyzer(YourAnalyzer())` at module level
"""

import difflib
import json
import logging
import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import ASSESSMENTS_DIR, MCP_BASELINES_DIR
from .persistence import save_json, load_json

logger = logging.getLogger("trust_layer.mcp_assess")

ASSESS_DAILY_LIMIT = 100  # max assess calls per api_key per day

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEVERITY_WEIGHT = {s: i for i, s in enumerate(_SEVERITIES)}


@dataclass
class Finding:
    analyzer: str
    severity: str      # info | low | medium | high | critical
    tool: str          # tool name, or "" for server-level findings
    message: str


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Abstract analyzer
# ---------------------------------------------------------------------------

class BaseAnalyzer(ABC):
    """Abstract base class for MCP security analyzers.

    To add a new analyzer:
    1. Subclass BaseAnalyzer
    2. Set `name`
    3. Implement `analyze(tools, baseline) -> list[Finding]`
    4. Call `register_analyzer(YourAnalyzer())` at module level
    """

    name: str

    @abstractmethod
    def analyze(self, tools: list[dict], baseline: Optional[dict]) -> list[Finding]:
        """Analyze tools against baseline. Return list of findings.

        tools: current manifest tools list
        baseline: previously stored baseline dict, or None on first call
        """
        ...


# ---------------------------------------------------------------------------
# Analyzer registry
# ---------------------------------------------------------------------------

_ANALYZER_REGISTRY: dict[str, BaseAnalyzer] = {}


def register_analyzer(analyzer: BaseAnalyzer) -> None:
    """Register an analyzer. Called at module level for each implementation."""
    _ANALYZER_REGISTRY[analyzer.name] = analyzer


def get_analyzer(name: str) -> Optional[BaseAnalyzer]:
    """Get analyzer by name."""
    return _ANALYZER_REGISTRY.get(name)


def get_all_analyzers() -> list[BaseAnalyzer]:
    """Return all registered analyzers."""
    return list(_ANALYZER_REGISTRY.values())


# ---------------------------------------------------------------------------
# Built-in analyzer 1: Permission
# ---------------------------------------------------------------------------

_DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    # (regex_pattern, capability_name, severity)
    (r"\bwrite\b|\bdelete\b|\bremove\b|\boverwrite\b", "filesystem_write", "high"),
    (r"\bexec\b|\bshell\b|\brun\b|\bspawn\b|\bcommand\b|\bsubprocess\b", "code_execution", "critical"),
    (r"\benv\b|\benvironment\b|\bsecret\b|\bcredential\b|\bpassword\b|\btoken\b", "env_access", "high"),
    (r"\bhttp\b|\bhttps\b|\bfetch\b|\brequest\b|\bdownload\b|\bupload\b|\bwebhook\b", "network_access", "medium"),
]


class PermissionAnalyzer(BaseAnalyzer):
    """Flags tools with dangerous capability patterns in name or description."""

    name = "permissions"

    def analyze(self, tools: list[dict], baseline: Optional[dict]) -> list[Finding]:
        findings = []
        for tool in tools:
            tool_name = tool.get("name", "")
            description = tool.get("description", "")
            text = f"{tool_name} {description}".lower()
            for pattern, capability, severity in _DANGEROUS_PATTERNS:
                if re.search(pattern, text):
                    findings.append(Finding(
                        analyzer=self.name,
                        severity=severity,
                        tool=tool_name,
                        message=f"Tool has '{capability}' capability pattern",
                    ))
                    break  # one finding per tool (highest match)
        return findings


register_analyzer(PermissionAnalyzer())


# ---------------------------------------------------------------------------
# Built-in analyzer 2: Description Drift
# ---------------------------------------------------------------------------

class DescriptionDriftAnalyzer(BaseAnalyzer):
    """Detects changes in tool descriptions since the last baseline."""

    name = "drift"

    def analyze(self, tools: list[dict], baseline: Optional[dict]) -> list[Finding]:
        if baseline is None:
            return []  # first call — no baseline to compare
        findings = []
        current = {t["name"]: t.get("description", "") for t in tools if "name" in t}
        previous = {
            t["name"]: t.get("description", "")
            for t in baseline.get("tools", [])
            if "name" in t
        }
        # New tools
        for name in set(current) - set(previous):
            findings.append(Finding(
                analyzer=self.name,
                severity="medium",
                tool=name,
                message="New tool added since last baseline",
            ))
        # Removed tools
        for name in set(previous) - set(current):
            findings.append(Finding(
                analyzer=self.name,
                severity="medium",
                tool=name,
                message="Tool removed since last baseline",
            ))
        # Changed descriptions
        for name in set(current) & set(previous):
            old_desc = previous[name]
            new_desc = current[name]
            if old_desc != new_desc:
                ratio = difflib.SequenceMatcher(None, old_desc, new_desc).ratio()
                severity = "high" if ratio < 0.5 else "medium"
                findings.append(Finding(
                    analyzer=self.name,
                    severity=severity,
                    tool=name,
                    message=f"Description changed (similarity {ratio:.0%})",
                ))
        return findings


register_analyzer(DescriptionDriftAnalyzer())


# ---------------------------------------------------------------------------
# Built-in analyzer 3: Version Tracking
# ---------------------------------------------------------------------------

def _parse_major(version_str: str) -> Optional[int]:
    """Extract major version number from a semver-ish string."""
    m = re.match(r"v?(\d+)", version_str.strip())
    return int(m.group(1)) if m else None


class VersionTrackingAnalyzer(BaseAnalyzer):
    """Detects server version regressions or major version changes."""

    name = "version"

    def analyze(self, tools: list[dict], baseline: Optional[dict]) -> list[Finding]:
        if baseline is None:
            return []
        current_v = baseline.get("_current_server_version")  # set by build_assessment
        previous_v = baseline.get("server_version")
        if not current_v or not previous_v:
            return []
        findings = []
        prev_major = _parse_major(previous_v)
        curr_major = _parse_major(current_v)
        if prev_major is not None and curr_major is not None:
            if curr_major < prev_major:
                findings.append(Finding(
                    analyzer=self.name,
                    severity="high",
                    tool="",
                    message=f"Server version downgrade: {previous_v} → {current_v}",
                ))
            elif curr_major > prev_major:
                findings.append(Finding(
                    analyzer=self.name,
                    severity="medium",
                    tool="",
                    message=f"Major version change: {previous_v} → {current_v}",
                ))
        return findings


register_analyzer(VersionTrackingAnalyzer())


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------

def _sanitize_server_id(server_id: str) -> str:
    """Sanitize server_id to prevent path traversal."""
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", server_id)[:64]
    return sanitized or "default"


def _baseline_path(fingerprint: str, server_id: str) -> Path:
    safe_sid = _sanitize_server_id(server_id)
    fp_prefix = fingerprint[:16] if fingerprint else "anonymous"
    return MCP_BASELINES_DIR / fp_prefix / f"{safe_sid}.json"


def save_baseline(fingerprint: str, server_id: str, data: dict) -> Path:
    path = _baseline_path(fingerprint, server_id)
    save_json(path, data)
    return path


def load_baseline(fingerprint: str, server_id: str) -> Optional[dict]:
    path = _baseline_path(fingerprint, server_id)
    if not path.exists():
        return None
    return load_json(path)


# ---------------------------------------------------------------------------
# Assessment builder
# ---------------------------------------------------------------------------

def generate_assess_id() -> str:
    """Generate assessment ID: asr_YYYYMMDD_HHMMSS_<6hex>."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d_%H%M%S")
    rand = secrets.token_hex(3)
    return f"asr_{ts}_{rand}"


def _compute_risk_score(findings: list[Finding]) -> int:
    """Compute a 0–100 risk score from findings. Higher = riskier."""
    if not findings:
        return 0
    weights = {"info": 1, "low": 5, "medium": 15, "high": 30, "critical": 50}
    raw = sum(weights.get(f.severity, 0) for f in findings)
    return min(100, raw)


def build_assessment(
    fingerprint: str,
    server_id: str,
    tools: list[dict],
    server_version: Optional[str],
) -> dict:
    """Run all registered analyzers, update baseline, return assessment dict."""
    baseline = load_baseline(fingerprint, server_id)

    # Inject current server_version into a transient baseline copy for VersionTrackingAnalyzer
    analysis_baseline = None
    if baseline is not None:
        analysis_baseline = dict(baseline)
        analysis_baseline["_current_server_version"] = server_version or ""

    all_findings: list[Finding] = []
    for analyzer in get_all_analyzers():
        try:
            findings = analyzer.analyze(tools, analysis_baseline)
            all_findings.extend(findings)
        except Exception as e:
            logger.warning("Analyzer %s failed: %s", analyzer.name, e)

    # Compute drift summary for response
    drift_detected = any(f.analyzer == "drift" for f in all_findings)
    drift_summary: dict = {}
    if baseline is not None:
        prev_names = {t["name"] for t in baseline.get("tools", []) if "name" in t}
        curr_names = {t["name"] for t in tools if "name" in t}
        drift_summary = {
            "new_tools": sorted(curr_names - prev_names),
            "removed_tools": sorted(prev_names - curr_names),
            "changed": sorted(
                f.tool for f in all_findings
                if f.analyzer == "drift" and f.tool in prev_names & curr_names
            ),
        }

    # Update baseline
    new_baseline = {
        "tools": tools,
        "server_version": server_version,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_baseline(fingerprint, server_id, new_baseline)

    assess_id = generate_assess_id()
    now_iso = datetime.now(timezone.utc).isoformat()

    assessment = {
        "assess_id": assess_id,
        "server_id": server_id,
        "assessed_at": now_iso,
        "risk_score": _compute_risk_score(all_findings),
        "findings": [
            {"analyzer": f.analyzer, "severity": f.severity,
             "tool": f.tool, "message": f.message}
            for f in all_findings
        ],
        "drift_detected": drift_detected,
        "drift_summary": drift_summary,
        "baseline_status": "updated" if baseline is not None else "created",
        "_links": {
            "pricing": "https://arkforge.tech/en/pricing.html?utm_source=assess_api&utm_medium=json_response",
            "docs": "https://arkforge.tech/en/assess.html",
            "hint": "Continuous MCP monitoring & drift alerts available on paid plans.",
        },
    }

    # Persist assessment artifact
    try:
        save_json(ASSESSMENTS_DIR / f"{assess_id}.json", assessment)
    except Exception as e:
        logger.warning("Could not persist assessment %s: %s", assess_id, e)

    return assessment
