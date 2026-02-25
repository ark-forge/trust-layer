"""HTML templates for proof visualization — zero dependencies, self-contained."""

import html


def _esc(value) -> str:
    """Escape user data for safe HTML rendering (anti-XSS)."""
    if value is None:
        return ""
    return html.escape(str(value))


def render_proof_page(proof: dict, integrity_verified: bool) -> str:
    """Render a self-contained HTML page for a proof record.

    Badge colors:
    - Green #22c55e: integrity verified
    - Orange #f59e0b: OTS pending (integrity OK but timestamp not confirmed)
    - Red #ef4444: integrity check failed
    """
    proof_id = _esc(proof.get("proof_id", ""))
    timestamp = _esc(proof.get("timestamp", ""))
    hashes = proof.get("hashes", {})
    parties = proof.get("parties", {})
    payment = proof.get("payment", {})
    ots = proof.get("opentimestamps", {})
    identity_consistent = proof.get("identity_consistent")

    ots_status = ots.get("status", "unknown")

    if not integrity_verified:
        badge_color = "#ef4444"
        badge_text = "INTEGRITY FAILED"
        badge_desc = "The chain hash does not match. This proof may have been tampered with."
    elif ots_status == "verified":
        badge_color = "#22c55e"
        badge_text = "VERIFIED"
        badge_desc = "Integrity verified. Timestamp confirmed on Bitcoin blockchain."
    else:
        badge_color = "#f59e0b"
        badge_text = "VERIFIED — TIMESTAMP PENDING"
        badge_desc = "Integrity verified. OpenTimestamps confirmation in progress."

    # Build identity section (conditional)
    identity_html = ""
    agent_identity = parties.get("agent_identity")
    if agent_identity:
        consistent_badge = ""
        if identity_consistent is True:
            consistent_badge = '<span style="color:#22c55e;font-weight:600">Consistent</span>'
        elif identity_consistent is False:
            consistent_badge = '<span style="color:#ef4444;font-weight:600">Mismatch detected</span>'
        identity_html = f"""
        <div class="section">
            <h2>Identity</h2>
            <div class="row"><span class="label">Agent</span><span class="value">{_esc(agent_identity)}</span></div>
            <div class="row"><span class="label">Version</span><span class="value">{_esc(parties.get("agent_version", ""))}</span></div>
            <div class="row"><span class="label">Consistency</span><span class="value">{consistent_badge}</span></div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ArkForge Proof — {proof_id}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:2rem 1rem}}
.container{{max-width:720px;margin:0 auto}}
.header{{text-align:center;margin-bottom:2rem}}
.header h1{{font-size:1.5rem;font-weight:700;color:#f8fafc;margin-bottom:0.5rem}}
.header .subtitle{{color:#94a3b8;font-size:0.875rem}}
.badge{{display:inline-block;padding:0.5rem 1.5rem;border-radius:9999px;font-weight:700;font-size:0.875rem;color:#fff;background:{badge_color};margin:1rem 0}}
.badge-desc{{color:#94a3b8;font-size:0.8rem;margin-bottom:1.5rem}}
.section{{background:#1e293b;border-radius:0.75rem;padding:1.25rem;margin-bottom:1rem}}
.section h2{{font-size:0.9rem;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.75rem}}
.row{{display:flex;justify-content:space-between;padding:0.4rem 0;border-bottom:1px solid #334155;flex-wrap:wrap;gap:0.25rem}}
.row:last-child{{border-bottom:none}}
.label{{color:#94a3b8;font-size:0.85rem;min-width:120px}}
.value{{color:#f1f5f9;font-size:0.85rem;word-break:break-all;text-align:right;flex:1}}
.hash{{font-family:"Fira Code",monospace;font-size:0.75rem;color:#7dd3fc}}
.footer{{text-align:center;margin-top:2rem;color:#475569;font-size:0.75rem}}
.footer a{{color:#38bdf8;text-decoration:none}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>ArkForge Trust Layer</h1>
        <div class="subtitle">Turning API executions into independently verifiable events.</div>
        <div class="badge">{badge_text}</div>
        <div class="badge-desc">{badge_desc}</div>
    </div>

    <div class="section">
        <h2>Proof</h2>
        <div class="row"><span class="label">Proof ID</span><span class="value">{proof_id}</span></div>
        <div class="row"><span class="label">Timestamp</span><span class="value">{timestamp}</span></div>
        <div class="row"><span class="label">OTS Status</span><span class="value">{_esc(ots_status)}</span></div>
    </div>

    <div class="section">
        <h2>Hashes</h2>
        <div class="row"><span class="label">Request</span><span class="value hash">{_esc(hashes.get("request", ""))}</span></div>
        <div class="row"><span class="label">Response</span><span class="value hash">{_esc(hashes.get("response", ""))}</span></div>
        <div class="row"><span class="label">Chain</span><span class="value hash">{_esc(hashes.get("chain", ""))}</span></div>
    </div>

    <div class="section">
        <h2>Parties</h2>
        <div class="row"><span class="label">Buyer</span><span class="value hash">{_esc(parties.get("buyer_fingerprint", ""))}</span></div>
        <div class="row"><span class="label">Seller</span><span class="value">{_esc(parties.get("seller", ""))}</span></div>
    </div>
{identity_html}
    <div class="section">
        <h2>Payment</h2>
        <div class="row"><span class="label">Amount</span><span class="value">{_esc(payment.get("amount", ""))} {_esc(payment.get("currency", "").upper())}</span></div>
        <div class="row"><span class="label">Status</span><span class="value">{_esc(payment.get("status", ""))}</span></div>
        <div class="row"><span class="label">Provider</span><span class="value">{_esc(payment.get("provider", ""))}</span></div>
        <div class="row"><span class="label">Transaction</span><span class="value hash">{_esc(payment.get("transaction_id", ""))}</span></div>
    </div>

    <div class="footer">
        <p>Verified by <a href="https://arkforge.fr">ArkForge Trust Layer</a></p>
        <p style="margin-top:0.5rem">This proof is independently verifiable. The chain hash can be recomputed from the request hash, response hash, payment ID, timestamp, and party fingerprints.</p>
    </div>
</div>
</body>
</html>"""
