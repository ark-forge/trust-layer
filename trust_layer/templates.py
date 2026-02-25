"""HTML templates for proof visualization — zero dependencies, self-contained."""

import html
from datetime import datetime


def _esc(value) -> str:
    """Escape user data for safe HTML rendering (anti-XSS)."""
    if value is None:
        return ""
    return html.escape(str(value))


def _format_date(timestamp: str) -> str:
    """Convert ISO timestamp to human-readable date."""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y, %H:%M UTC")
    except (ValueError, AttributeError):
        return timestamp or ""


def _format_amount(payment: dict) -> str:
    """Format payment amount for display."""
    amount = payment.get("amount", "")
    currency = payment.get("currency", "").upper()
    if currency == "EUR":
        return f"\u20ac{amount}"
    elif currency == "USD":
        return f"${amount}"
    elif currency == "GBP":
        return f"\u00a3{amount}"
    return f"{amount} {currency}"


def render_proof_page(proof: dict, integrity_verified: bool) -> str:
    """Render a self-contained HTML proof page.

    This page is a receipt + certificate + verdict.
    Designed for humans first, engineers second.
    """
    proof_id = _esc(proof.get("proof_id", ""))
    timestamp = proof.get("timestamp", "")
    human_date = _esc(_format_date(timestamp))
    hashes = proof.get("hashes", {})
    parties = proof.get("parties", {})
    payment = proof.get("payment", {})
    ots = proof.get("opentimestamps", {})
    archive_org = proof.get("archive_org") or {}
    identity_consistent = proof.get("identity_consistent")
    verification_url = _esc(proof.get("verification_url", ""))

    ots_status = ots.get("status", "unknown")
    seller = _esc(parties.get("seller", ""))
    agent_identity = parties.get("agent_identity")
    initiated_by = _esc(agent_identity) if agent_identity else "Software agent"
    amount_display = _esc(_format_amount(payment))
    execution_status = "Successful" if integrity_verified else "Integrity check failed"
    receipt_url = _esc(payment.get("receipt_url", ""))

    # --- Verdict ---
    if not integrity_verified:
        verdict_bg = "#7f1d1d"
        verdict_border = "#ef4444"
        verdict_icon = "\u26a0\ufe0f"
        verdict_text = "INTEGRITY CHECK FAILED"
        verdict_sub = "The chain hash does not match. This proof may have been tampered with."
    elif ots_status == "verified":
        verdict_bg = "#052e16"
        verdict_border = "#22c55e"
        verdict_icon = "\u2705"
        verdict_text = "VERIFIED AUTONOMOUS TRANSACTION"
        verdict_sub = "This action was executed and paid by a software agent. Cryptographically certified by ArkForge."
    else:
        verdict_bg = "#052e16"
        verdict_border = "#22c55e"
        verdict_icon = "\u2705"
        verdict_text = "VERIFIED AUTONOMOUS TRANSACTION"
        verdict_sub = "This action was executed and paid by a software agent. Cryptographically certified by ArkForge. Timestamp pending Bitcoin confirmation."

    # --- Witnesses ---
    stripe_witness = f'<a href="{receipt_url}" style="color:#38bdf8;text-decoration:none">Stripe</a>' if receipt_url else "Stripe"

    ots_color = "#22c55e" if ots_status == "verified" else "#f59e0b"
    ots_label = "confirms date cannot be altered" if ots_status == "verified" else "timestamp pending confirmation"

    archive_snapshot_url = archive_org.get("snapshot_url", "")
    archive_has_snapshot = bool(archive_snapshot_url)
    archive_color = "#22c55e" if archive_has_snapshot else "#475569"
    archive_name = f'<a href="{_esc(archive_snapshot_url)}" style="color:#38bdf8;text-decoration:none">Archive.org</a>' if archive_has_snapshot else "Archive.org"
    archive_desc = "public snapshot preserved" if archive_has_snapshot else "snapshot not yet available"

    # --- Identity row (conditional) ---
    identity_row = ""
    if agent_identity:
        identity_row = f'<div class="row"><span class="label">Initiated by</span><span class="val">{initiated_by}</span></div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ArkForge Proof \u2014 {proof_id}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:2rem 1rem}}
.container{{max-width:680px;margin:0 auto}}
.verdict{{background:{verdict_bg};border:2px solid {verdict_border};border-radius:1rem;padding:2rem;text-align:center;margin-bottom:2rem}}
.verdict .icon{{font-size:2.5rem;margin-bottom:0.5rem}}
.verdict h1{{font-size:1.4rem;font-weight:800;color:#f8fafc;letter-spacing:0.02em;margin-bottom:0.5rem}}
.verdict p{{color:#94a3b8;font-size:0.9rem;line-height:1.5}}
.card{{background:#1e293b;border-radius:0.75rem;padding:1.5rem;margin-bottom:1rem}}
.card h2{{font-size:0.8rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:1rem}}
.row{{display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid #334155;align-items:center;gap:0.5rem}}
.row:last-child{{border-bottom:none}}
.label{{color:#94a3b8;font-size:0.9rem;flex-shrink:0}}
.val{{color:#f1f5f9;font-size:0.9rem;text-align:right;word-break:break-all}}
.val a{{color:#38bdf8;text-decoration:none}}
.trust-point{{display:flex;align-items:flex-start;gap:0.75rem;padding:0.6rem 0}}
.trust-point .dot{{flex-shrink:0;width:8px;height:8px;border-radius:50%;margin-top:6px}}
.trust-point p{{color:#cbd5e1;font-size:0.875rem;line-height:1.4}}
.witness{{display:flex;align-items:center;gap:0.6rem;padding:0.5rem 0;border-bottom:1px solid #334155}}
.witness:last-child{{border-bottom:none}}
.witness .dot{{flex-shrink:0;width:8px;height:8px;border-radius:50%}}
.witness .name{{color:#f1f5f9;font-size:0.875rem;font-weight:500;min-width:100px}}
.witness .desc{{color:#94a3b8;font-size:0.85rem}}
details{{background:#1e293b;border-radius:0.75rem;margin-bottom:1rem}}
summary{{padding:1rem 1.5rem;cursor:pointer;color:#64748b;font-size:0.85rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;list-style:none}}
summary::-webkit-details-marker{{display:none}}
summary::before{{content:"\u25b6 ";font-size:0.7rem}}
details[open] summary::before{{content:"\u25bc "}}
.tech-inner{{padding:0 1.5rem 1.5rem}}
.tech-row{{display:flex;justify-content:space-between;padding:0.35rem 0;border-bottom:1px solid #334155;gap:0.5rem}}
.tech-row:last-child{{border-bottom:none}}
.tech-label{{color:#64748b;font-size:0.8rem;flex-shrink:0;min-width:100px}}
.tech-val{{color:#7dd3fc;font-family:"Fira Code","SF Mono",monospace;font-size:0.72rem;text-align:right;word-break:break-all}}
.standalone{{color:#94a3b8;font-size:0.85rem;text-align:center;font-style:italic;margin:1.5rem 0}}
.verify-link{{display:block;text-align:center;margin:1.5rem 0}}
.verify-link a{{display:inline-block;padding:0.6rem 1.5rem;background:#1e293b;border:1px solid #334155;border-radius:0.5rem;color:#38bdf8;font-size:0.85rem;text-decoration:none;font-weight:500}}
.verify-link a:hover{{border-color:#38bdf8;background:#0f172a}}
.footer{{text-align:center;margin-top:2rem;padding-top:1.5rem;border-top:1px solid #1e293b}}
.footer .tagline{{color:#64748b;font-size:0.8rem;margin-bottom:0.5rem}}
.footer a{{color:#38bdf8;text-decoration:none}}
.footer .arkforge{{color:#475569;font-size:0.75rem;margin-top:0.75rem}}
</style>
</head>
<body>
<div class="container">

    <!-- 1. VERDICT -->
    <div class="verdict">
        <div class="icon">{verdict_icon}</div>
        <h1>{verdict_text}</h1>
        <p>{verdict_sub}</p>
    </div>

    <!-- 2. HUMAN SUMMARY -->
    <div class="card">
        <h2>Transaction receipt</h2>
        <div class="row"><span class="label">Service</span><span class="val">{seller}</span></div>
{identity_row}
        <div class="row"><span class="label">Payment</span><span class="val">{amount_display}</span></div>
        <div class="row"><span class="label">Execution</span><span class="val">{_esc(execution_status)}</span></div>
        <div class="row"><span class="label">Date</span><span class="val">{human_date}</span></div>
        <div class="row"><span class="label">Proof ID</span><span class="val">{proof_id}</span></div>
    </div>

    <!-- 3. WHY TRUSTWORTHY -->
    <div class="card">
        <h2>Why this proof can be trusted</h2>
        <div class="trust-point">
            <div class="dot" style="background:#22c55e"></div>
            <p>Payment verified independently by Stripe</p>
        </div>
        <div class="trust-point">
            <div class="dot" style="background:#22c55e"></div>
            <p>Execution integrity secured using cryptographic hashing</p>
        </div>
        <div class="trust-point">
            <div class="dot" style="background:{ots_color}"></div>
            <p>Timestamp anchored outside ArkForge infrastructure via OpenTimestamps</p>
        </div>
    </div>

    <!-- 4. INDEPENDENT WITNESSES -->
    <div class="card">
        <h2>Independent verification sources</h2>
        <div class="witness">
            <div class="dot" style="background:#22c55e"></div>
            <span class="name">{stripe_witness}</span>
            <span class="desc">\u2014 confirms payment occurred</span>
        </div>
        <div class="witness">
            <div class="dot" style="background:{ots_color}"></div>
            <span class="name">Bitcoin</span>
            <span class="desc">\u2014 {_esc(ots_label)}</span>
        </div>
        <div class="witness">
            <div class="dot" style="background:{archive_color}"></div>
            <span class="name">{archive_name}</span>
            <span class="desc">\u2014 {_esc(archive_desc)}</span>
        </div>
    </div>

    <!-- 6. STANDALONE TRUST STATEMENT -->
    <p class="standalone">You do not need to trust ArkForge to verify this proof.</p>

    <!-- 7. VERIFY BUTTON -->
    <div class="verify-link">
        <a href="{verification_url}?format=json">Verify this proof via API \u2192</a>
    </div>

    <!-- 5. COLLAPSIBLE TECHNICAL DETAILS -->
    <details>
        <summary>Technical verification data</summary>
        <div class="tech-inner">
            <div class="tech-row"><span class="tech-label">Chain hash</span><span class="tech-val">{_esc(hashes.get("chain", ""))}</span></div>
            <div class="tech-row"><span class="tech-label">Request hash</span><span class="tech-val">{_esc(hashes.get("request", ""))}</span></div>
            <div class="tech-row"><span class="tech-label">Response hash</span><span class="tech-val">{_esc(hashes.get("response", ""))}</span></div>
            <div class="tech-row"><span class="tech-label">Payment ID</span><span class="tech-val">{_esc(payment.get("transaction_id", ""))}</span></div>
            <div class="tech-row"><span class="tech-label">Buyer</span><span class="tech-val">{_esc(parties.get("buyer_fingerprint", ""))}</span></div>
            <div class="tech-row"><span class="tech-label">Seller</span><span class="tech-val">{seller}</span></div>
            <div class="tech-row"><span class="tech-label">Timestamp</span><span class="tech-val">{_esc(timestamp)}</span></div>
            <div class="tech-row"><span class="tech-label">OTS status</span><span class="tech-val">{_esc(ots_status)}</span></div>
            <div class="tech-row"><span class="tech-label">Algorithm</span><span class="tech-val">SHA-256(request + response + payment_id + timestamp + buyer + seller)</span></div>
        </div>
    </details>

    <!-- 8. FOOTER -->
    <div class="footer">
        <div class="tagline">ArkForge is a certifying proxy that turns API executions into independently verifiable events.</div>
        <div class="arkforge"><a href="https://arkforge.fr">arkforge.fr</a></div>
    </div>

</div>
</body>
</html>"""
