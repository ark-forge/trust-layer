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
    hashes = proof.get("hashes") or {}
    parties = proof.get("parties") or {}
    payment = proof.get("certification_fee") or {}
    ots = proof.get("timestamp_authority") or {}
    tsr_url = _esc(ots.get("tsr_url", ""))
    # Pre-compute to avoid backslash-in-fstring-expression (Python < 3.12 restriction)
    tsr_download_link = (
        f'<a href="{tsr_url}" download>Download TSR (RFC\u00a03161) \u2192</a>'
        if tsr_url else ""
    )
    archive_org = proof.get("archive_org") or {}
    identity_consistent = proof.get("identity_consistent")
    verification_url = _esc(proof.get("verification_url", ""))
    spec_version = proof.get("spec_version")
    upstream_timestamp = proof.get("upstream_timestamp")
    arkforge_signature = proof.get("arkforge_signature")
    arkforge_pubkey = proof.get("arkforge_pubkey")

    provider_payment = proof.get("provider_payment") or {}
    transaction_success = proof.get("transaction_success")
    upstream_status_code = proof.get("upstream_status_code")
    is_disputed = proof.get("disputed", False)
    dispute_id = proof.get("dispute_id")

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
        verdict_sub = "This action was executed and paid by a software agent. Cryptographically certified by ArkForge."

    # --- Witnesses ---
    is_free_tier = payment.get("method") == "none" or payment.get("status") == "free_tier"
    is_prepaid = payment.get("method") == "prepaid_credit"
    if is_free_tier:
        payment_color = "#475569"
        payment_witness = "Stripe"
        payment_desc = "not applicable (free tier)"
        payment_line = "Payment not required (free tier)"
    elif is_prepaid:
        payment_color = "#22c55e"
        payment_witness = "Prepaid credits"
        payment_desc = "deducted from prepaid balance"
        has_provider_payment = bool(provider_payment and provider_payment.get("receipt_url"))
        payment_line = (
            "ArkForge certification fee paid via prepaid credits"
            if has_provider_payment
            else "Payment via prepaid credits"
        )
    else:
        payment_color = "#22c55e"
        payment_witness = f'<a href="{receipt_url}" style="color:#38bdf8;text-decoration:none">Stripe</a>' if receipt_url else "Stripe"
        payment_desc = "confirms payment occurred"
        payment_line = "Payment verified independently by Stripe"

    ots_color = "#22c55e" if ots_status == "verified" else "#f59e0b"
    if ots_status == "verified":
        ots_label = "certified timestamp confirms date cannot be altered"
    else:
        ots_label = "timestamp not yet available"

    archive_snapshot_url = archive_org.get("snapshot_url", "")
    archive_has_snapshot = bool(archive_snapshot_url)
    archive_color = "#22c55e" if archive_has_snapshot else "#475569"
    archive_name = f'<a href="{_esc(archive_snapshot_url)}" style="color:#38bdf8;text-decoration:none">Archive.org</a>' if archive_has_snapshot else "Archive.org"
    archive_desc = "public snapshot preserved" if archive_has_snapshot else "snapshot not yet available"

    # --- Signature ---
    has_signature = bool(arkforge_signature)
    sig_color = "#22c55e" if has_signature else "#475569"
    sig_label = "origin authenticated by Ed25519 digital signature" if has_signature else "signature not available"

    # --- Payment evidence section (conditional) ---
    provider_payment_html = ""
    if provider_payment and provider_payment.get("receipt_url"):
        pe_status = provider_payment.get("verification_status", "unknown")
        pe_color = "#22c55e" if pe_status == "fetched" else "#ef4444"
        pe_label = f"Fetched from {_esc(provider_payment.get('type', 'unknown')).capitalize()}" if pe_status == "fetched" else "Fetch failed"
        pe_hash = _esc(provider_payment.get("receipt_content_hash", ""))
        pe_url = _esc(provider_payment.get("receipt_url", ""))
        pe_parsing = provider_payment.get("parsing_status", "not_attempted")
        pe_fields = provider_payment.get("parsed_fields") or {}

        pe_parsed_rows = ""
        if pe_fields.get("amount") is not None:
            currency_display = (pe_fields.get("currency") or "").upper()
            pe_parsed_rows += f'<div class="row"><span class="label">Amount</span><span class="val">{_esc(str(pe_fields["amount"]))} {_esc(currency_display)}</span></div>'
        if pe_fields.get("status"):
            pe_parsed_rows += f'<div class="row"><span class="label">Status</span><span class="val">{_esc(pe_fields["status"])}</span></div>'
        if pe_fields.get("date"):
            pe_parsed_rows += f'<div class="row"><span class="label">Date</span><span class="val">{_esc(pe_fields["date"])}</span></div>'

        provider_payment_html = f"""
    <div class="card">
        <h2>Provider payment</h2>
        <p style="color:#94a3b8;font-size:0.8rem;margin-bottom:1rem">Paid directly from agent to provider \u2014 not processed by ArkForge</p>
        <div class="row"><span class="label">Verification</span><span class="val" style="color:{pe_color}">{pe_label}</span></div>
        {"" if not pe_hash else f'<div class="row"><span class="label">Receipt hash</span><span class="val" style="font-family:monospace;font-size:0.75rem">{pe_hash}</span></div>'}
{pe_parsed_rows}
        {"" if not pe_url else f'<div class="row"><span class="label">Receipt</span><span class="val"><a href="{pe_url}" style="color:#38bdf8;text-decoration:none">View original receipt &#8599;</a></span></div>'}
    </div>"""

    # --- Dispute alert (conditional) ---
    dispute_html = ""
    if is_disputed:
        dispute_html = f"""
    <div class="card" style="border:1px solid #f59e0b;background:#451a03">
        <h2 style="color:#fbbf24">Disputed proof</h2>
        <div class="row"><span class="label">Status</span><span class="val" style="color:#fbbf24">This proof has been disputed</span></div>
        {"" if not dispute_id else f'<div class="row"><span class="label">Dispute ID</span><span class="val" style="font-family:monospace;font-size:0.8rem">{_esc(dispute_id)}</span></div>'}
    </div>"""

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
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230B0F14'/%3E%3Cline x1='12' y1='32' x2='52' y2='32' stroke='%2300E5FF' stroke-width='5' stroke-linecap='round'/%3E%3Ccircle cx='32' cy='32' r='14' stroke='%23FFF' stroke-width='4' fill='none'/%3E%3Ccircle cx='32' cy='32' r='5' fill='%2300E5FF'/%3E%3C/svg%3E">
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
.witness{{display:flex;align-items:center;gap:0.6rem;padding:0.5rem 0;border-bottom:1px solid #334155;flex-wrap:wrap}}
.witness:last-child{{border-bottom:none}}
.witness .dot{{flex-shrink:0;width:8px;height:8px;border-radius:50%}}
.witness .name{{color:#f1f5f9;font-size:0.875rem;font-weight:500}}
.witness .desc{{color:#94a3b8;font-size:0.85rem}}
@media(max-width:480px){{.witness .desc{{width:100%;padding-left:20px}}.tech-val{{font-size:0.65rem}}}}
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
.cta-banner{{text-align:center;margin:1.5rem 0;padding:1rem 1.5rem;background:#1e293b;border:1px solid #334155;border-radius:0.75rem}}
.cta-banner p{{color:#94a3b8;font-size:0.8rem;line-height:1.6}}
.cta-banner a{{color:#818cf8;font-weight:500;text-decoration:none}}
.cta-banner a:hover{{text-decoration:underline;color:#a5b4fc}}
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
        <div class="row"><span class="label">{"Certification fee" if provider_payment and provider_payment.get("receipt_url") else "Payment"}</span><span class="val">{amount_display}</span></div>
        <div class="row"><span class="label">Execution</span><span class="val">{_esc(execution_status)}</span></div>
        {"" if transaction_success is None else f'<div class="row"><span class="label">Upstream</span><span class="val" style="color:{"#22c55e" if transaction_success else "#ef4444"}">{"Success" if transaction_success else "Failed"}{f" (HTTP {upstream_status_code})" if upstream_status_code else ""}</span></div>'}
        <div class="row"><span class="label">Date</span><span class="val">{human_date}</span></div>
        <div class="row"><span class="label">Proof ID</span><span class="val">{proof_id}</span></div>
    </div>

    <!-- 3. WHY TRUSTWORTHY -->
    <div class="card">
        <h2>Why this proof can be trusted</h2>
        <div class="trust-point">
            <div class="dot" style="background:{payment_color}"></div>
            <p>{payment_line}</p>
        </div>
        <div class="trust-point">
            <div class="dot" style="background:#22c55e"></div>
            <p>Execution integrity secured using cryptographic hashing</p>
        </div>
        <div class="trust-point">
            <div class="dot" style="background:{ots_color}"></div>
            <p>Timestamp anchored outside ArkForge infrastructure via RFC 3161 Timestamp Authority</p>
        </div>
        <div class="trust-point">
            <div class="dot" style="background:{sig_color}"></div>
            <p>Origin authenticated by ArkForge\u2019s Ed25519 digital signature</p>
        </div>
    </div>

    <!-- 4. INDEPENDENT WITNESSES -->
    <div class="card">
        <h2>Independent verification sources</h2>
        <div class="witness">
            <div class="dot" style="background:{payment_color}"></div>
            <span class="name">{payment_witness}</span>
            <span class="desc">\u2014 {payment_desc}</span>
        </div>
        <div class="witness">
            <div class="dot" style="background:{ots_color}"></div>
            <span class="name">RFC 3161 Timestamp</span>
            <span class="desc">\u2014 {_esc(ots_label)}</span>
        </div>
        <div class="witness">
            <div class="dot" style="background:{sig_color}"></div>
            <span class="name">Ed25519 Signature</span>
            <span class="desc">\u2014 {_esc(sig_label)}</span>
        </div>
        <div class="witness">
            <div class="dot" style="background:{archive_color}"></div>
            <span class="name">{archive_name}</span>
            <span class="desc">\u2014 {_esc(archive_desc)}</span>
        </div>
    </div>

    <!-- 5a. DISPUTE ALERT -->
{dispute_html}

    <!-- 5b. EXTERNAL PAYMENT EVIDENCE -->
{provider_payment_html}

    <!-- 6. STANDALONE TRUST STATEMENT -->
    <p class="standalone">You do not need to trust ArkForge to verify this proof.</p>

    <!-- 7. VERIFY BUTTON -->
    <div class="verify-link">
        <a href="{verification_url}?format=json">Verify this proof via API \u2192</a>
        {tsr_download_link}
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
            {"" if not upstream_timestamp else f'<div class="tech-row"><span class="tech-label">Upstream time</span><span class="tech-val">{_esc(upstream_timestamp)}</span></div>'}
            <div class="tech-row"><span class="tech-label">TSA status</span><span class="tech-val">{_esc(ots_status)}</span></div>
            {"" if not arkforge_signature else f'<div class="tech-row"><span class="tech-label">Signature</span><span class="tech-val">{_esc(arkforge_signature)}</span></div>'}
            {"" if not arkforge_pubkey else f'<div class="tech-row"><span class="tech-label">Public key</span><span class="tech-val">{_esc(arkforge_pubkey)}</span></div>'}
            {"" if not spec_version else f'<div class="tech-row"><span class="tech-label">Spec version</span><span class="tech-val">{_esc(spec_version)}</span></div>'}
            {"" if not provider_payment.get("receipt_content_hash") else f'<div class="tech-row"><span class="tech-label">Receipt hash</span><span class="tech-val">{_esc(provider_payment.get("receipt_content_hash", ""))}</span></div>'}
            <div class="tech-row"><span class="tech-label">Algorithm</span><span class="tech-val">SHA-256(request + response + payment_id + timestamp + buyer + seller{" + upstream_timestamp" if upstream_timestamp else ""}{" + receipt_hash" if provider_payment.get("receipt_content_hash") else ""})</span></div>
        </div>
    </details>

    <!-- 8. CTA BANNER -->
    <div class="cta-banner">
        <p>This proof was generated by <a href="https://arkforge.fr/en/pricing?utm_source=proof_view&utm_medium=proof_page&utm_content=cta_banner">ArkForge Trust Layer</a> \u2014 Certify your own AI transactions \u2192 <a href="https://arkforge.fr/en/pricing?utm_source=proof_view&utm_medium=proof_page&utm_content=cta_banner">Get started free</a></p>
    </div>

    <!-- 9. FOOTER -->
    <div class="footer">
        <div class="tagline">ArkForge is a certifying proxy that turns API executions into independently verifiable events.</div>
        <div class="arkforge"><a href="https://arkforge.fr" style="display:inline-flex;align-items:center;gap:6px"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="20" height="20" style="vertical-align:middle"><rect width="64" height="64" rx="14" fill="#0B0F14"/><line x1="12" y1="32" x2="52" y2="32" stroke="#00E5FF" stroke-width="5" stroke-linecap="round"/><circle cx="32" cy="32" r="14" stroke="#FFF" stroke-width="4" fill="none"/><circle cx="32" cy="32" r="5" fill="#00E5FF"/></svg> arkforge.fr</a></div>
    </div>

</div>
</body>
</html>"""
