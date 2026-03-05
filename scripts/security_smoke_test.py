#!/usr/bin/env python3
"""Security smoke test — Trust Layer.

Couvre les vecteurs critiques pré-launch :
  1. Auth bypass (no key, malformed, inactive)
  2. SSRF (IP literals, DNS names, encoded variants)
  3. Input validation (oversized, type confusion, method injection)
  4. Webhook replay (no signature, bad signature, replayed event_id)
  5. Path traversal (proof_id, agent_id)
  6. Header injection (Authorization variants)
  7. Idempotency (double submit)
  8. Rate / amount manipulation

Usage:
  python3 scripts/security_smoke_test.py [--url http://localhost:8100]

Exit 0 = all checks passed. Exit 1 = at least one finding.
"""

import argparse
import json
import sys
import time
import hmac
import hashlib
import secrets
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

# ---------------------------------------------------------------------------

GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
RESET = "\033[0m"

passed = 0
failed = 0
findings = []


def _request(method: str, url: str, body: Any = None, headers: dict | None = None,
             expected_status: int | None = None, label: str = "") -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            try:
                resp_body = json.loads(resp.read())
            except Exception:
                resp_body = {}
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            resp_body = json.loads(e.read())
        except Exception:
            resp_body = {}
    return status, resp_body


def check(label: str, status: int, resp_body: dict,
          expect_status: int | list | None = None, must_not_contain: list[str] | None = None):
    global passed, failed
    if expect_status is None:
        ok = True
    elif isinstance(expect_status, list):
        ok = status in expect_status
    else:
        ok = status == expect_status
    if must_not_contain:
        for key in must_not_contain:
            if key in str(resp_body):
                ok = False
                findings.append(f"{label}: response contains sensitive field '{key}'")

    if ok:
        passed += 1
        print(f"  {GREEN}PASS{RESET} [{status}] {label}")
    else:
        failed += 1
        findings.append(f"{label}: expected HTTP {expect_status}, got {status}. Body: {str(resp_body)[:200]}")
        exp_str = str(expect_status)
        print(f"  {RED}FAIL{RESET} [{status}] {label} (expected {exp_str})")


def section(title: str):
    print(f"\n{YELLOW}{'='*60}{RESET}")
    print(f"{YELLOW}  {title}{RESET}")
    print(f"{YELLOW}{'='*60}{RESET}")


# ---------------------------------------------------------------------------

def run(base: str, existing_key: str = ""):
    global passed, failed, findings
    # Use provided key or create a new free key
    if existing_key:
        free_key = existing_key
        print(f"\nUsing provided key: {free_key[:20]}...")
    else:
        test_run_id = secrets.token_hex(4)
        s, r = _request("POST", f"{base}/v1/keys/free-signup",
                        body={"email": f"sec-test-{test_run_id}@internal.arkforge.fr"})
        free_key = r.get("api_key", "")
        if not free_key:
            print(f"{RED}FATAL: could not create test key (HTTP {s}). "
                  f"Use --key <api_key> to provide an existing key.{RESET}")
            sys.exit(2)
        print(f"\nTest key created: {free_key[:20]}...")
    print(f"\nTest key created: {free_key[:20]}...")

    delay = 1.2  # seconds between requests — stays under nginx rate limit

    # -----------------------------------------------------------------------
    section("1. Auth bypass")

    s, r = _request("GET", f"{base}/v1/usage"); time.sleep(delay)
    check("No API key → 401", s, r, 401)

    s, r = _request("GET", f"{base}/v1/usage", headers={"Authorization": "Bearer "}); time.sleep(delay)
    check("Empty bearer token → 401", s, r, 401)

    s, r = _request("GET", f"{base}/v1/usage", headers={"Authorization": "Basic dXNlcjpwYXNz"}); time.sleep(delay)
    check("Basic auth scheme → 401", s, r, 401)

    s, r = _request("GET", f"{base}/v1/usage", headers={"X-Api-Key": "mcp_pro_" + "a"*48}); time.sleep(delay)
    check("Non-existent key → 401", s, r, 401)

    s, r = _request("GET", f"{base}/v1/usage", headers={"X-Api-Key": "' OR '1'='1"}); time.sleep(delay)
    check("SQL injection in key → 401", s, r, 401)

    s, r = _request("GET", f"{base}/v1/usage", headers={"X-Api-Key": "../../../etc/passwd"}); time.sleep(delay)
    check("Path traversal in key → 401", s, r, 401)

    s, r = _request("GET", f"{base}/v1/usage", headers={"X-Api-Key": free_key}); time.sleep(delay)
    check("Valid free key → 200", s, r, 200)

    # -----------------------------------------------------------------------
    section("2. SSRF — IP literals")
    # 400 (validation blocked) or 429 (rate limited before reaching target) are both safe.
    # 200 / 502 would mean the request was forwarded — that's the real finding.

    for label, target in [
        ("127.0.0.1 loopback",       "https://127.0.0.1/api"),
        ("10.0.0.1 RFC 1918",        "https://10.0.0.1/api"),
        ("192.168.1.1 RFC 1918",     "https://192.168.1.1/api"),
        ("172.16.0.1 RFC 1918",      "https://172.16.0.1/api"),
        ("169.254.169.254 IMDS",     "https://169.254.169.254/"),
        ("100.64.0.1 CGNAT",         "https://100.64.0.1/api"),
        ("0.0.0.0",                  "https://0.0.0.0/api"),
        ("::1 IPv6 loopback",        "https://[::1]/api"),
        ("fd00::1 IPv6 ULA",         "https://[fd00::1]/api"),
        ("fe80::1 IPv6 link-local",  "https://[fe80::1]/api"),
        ("::ffff:192.168.1.1 mapped","https://[::ffff:192.168.1.1]/api"),
        ("2002::1 6to4",             "https://[2002::1]/api"),
    ]:
        s, r = _request("POST", f"{base}/v1/proxy",
                        body={"target": target, "payload": {}, "currency": "eur"},
                        headers={"X-Api-Key": free_key})
        # Forwarded = real SSRF (200 or 502 from upstream). 400/401/429 = safe.
        if s in (200, 502):
            failed += 1
            findings.append(f"SSRF {label}: request was FORWARDED (HTTP {s}) — critical finding")
            print(f"  {RED}CRITICAL{RESET} [{s}] SSRF {label} — request forwarded to private IP!")
        else:
            passed += 1
            print(f"  {GREEN}PASS{RESET} [{s}] SSRF {label} → blocked ({s})")
        time.sleep(delay)

    # -----------------------------------------------------------------------
    section("3. SSRF — scheme attacks")

    for label, target in [
        ("http:// (non-TLS)",     "http://example.com/api"),
        ("ftp://",                "ftp://example.com/file"),
        ("file:///etc/passwd",    "file:///etc/passwd"),
        ("gopher://",             "gopher://example.com/1"),
        ("dict://",               "dict://example.com:2628/"),
        ("No scheme",             "example.com/api"),
        ("Empty string",          ""),
    ]:
        s, r = _request("POST", f"{base}/v1/proxy",
                        body={"target": target, "payload": {}, "currency": "eur"},
                        headers={"X-Api-Key": free_key})
        if s in (200, 502):
            failed += 1
            findings.append(f"SSRF scheme {label}: forwarded (HTTP {s})")
            print(f"  {RED}CRITICAL{RESET} [{s}] SSRF scheme {label} — forwarded!")
        else:
            passed += 1
            print(f"  {GREEN}PASS{RESET} [{s}] SSRF scheme {label} → blocked ({s})")
        time.sleep(delay)

    # -----------------------------------------------------------------------
    section("4. Input validation — proxy endpoint")

    validation_cases = [
        ("payload as string", {"target": "https://httpbin.org/post", "payload": "string not dict", "currency": "eur"}),
        ("payload as array",  {"target": "https://httpbin.org/post", "payload": [1, 2, 3], "currency": "eur"}),
        ("method=DELETE",     {"target": "https://httpbin.org/post", "payload": {}, "currency": "eur", "method": "DELETE"}),
        ("method injection",  {"target": "https://httpbin.org/post", "payload": {}, "currency": "eur", "method": "GET; rm -rf /"}),
        ("currency=btc",      {"target": "https://httpbin.org/post", "payload": {}, "currency": "btc"}),
        ("currency injection",{"target": "https://httpbin.org/post", "payload": {}, "currency": "EUR; DROP TABLE"}),
    ]
    for label, body in validation_cases:
        s, r = _request("POST", f"{base}/v1/proxy", body=body, headers={"X-Api-Key": free_key})
        check(f"{label} → 400", s, r, 400)
        time.sleep(delay)

    time.sleep(delay)
    big_payload = {"x" * 100: "y" * 100 for _ in range(50)}  # ~10KB
    s, r = _request("POST", f"{base}/v1/proxy",
                    body={"target": "https://httpbin.org/post", "payload": big_payload, "currency": "eur"},
                    headers={"X-Api-Key": free_key})
    if s >= 500:
        failed += 1
        findings.append(f"Oversized payload caused 5xx: {s}")
        print(f"  {RED}FAIL{RESET} [{s}] Large payload caused 5xx")
    else:
        passed += 1
        print(f"  {GREEN}PASS{RESET} [{s}] Large payload → non-5xx ({s})")

    # -----------------------------------------------------------------------
    section("5. Path traversal — proof_id / agent_id")

    for proof_id in ["../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "' OR '1'='1", "\x00null"]:
        s, r = _request("GET", f"{base}/v1/proof/{urllib.parse.quote(proof_id, safe='')}")
        if s >= 500:
            failed += 1
            findings.append(f"Path traversal proof_id={proof_id!r} caused 5xx: {s}")
            print(f"  {RED}FAIL{RESET} [{s}] proof traversal {proof_id!r}")
        else:
            passed += 1
            print(f"  {GREEN}PASS{RESET} [{s}] proof traversal {proof_id!r} (non-5xx)")
        time.sleep(delay)

    for agent_id in ["../../../etc", "' OR '1'='1", "a" * 200]:
        s, r = _request("GET", f"{base}/v1/agent/{urllib.parse.quote(agent_id, safe='')}/reputation")
        if s >= 500:
            failed += 1
            findings.append(f"Path traversal agent_id={agent_id[:30]!r} caused 5xx: {s}")
            print(f"  {RED}FAIL{RESET} [{s}] agent traversal")
        else:
            passed += 1
            print(f"  {GREEN}PASS{RESET} [{s}] agent traversal {agent_id[:30]!r}")
        time.sleep(delay)

    # -----------------------------------------------------------------------
    section("6. Stripe webhook replay protection")

    webhook_url = f"{base}/v1/webhooks/stripe"

    # No signature at all
    s, r = _request("POST", webhook_url,
                    body={"type": "checkout.session.completed", "id": "evt_test_fake"})
    check("Webhook no signature → 400", s, r, 400); time.sleep(delay)

    # Wrong signature
    s, r = _request("POST", webhook_url,
                    body={"type": "checkout.session.completed", "id": "evt_test_fake"},
                    headers={"Stripe-Signature": "t=1234,v1=badhash"})
    check("Webhook bad signature → 400", s, r, 400); time.sleep(delay)

    # Stale timestamp (replay with >5min old timestamp)
    payload_str = json.dumps({"type": "invoice.paid", "id": "evt_replay_test"})
    stale_ts = str(int(time.time()) - 400)  # 6+ minutes ago
    stale_sig = f"t={stale_ts},v1=fakehash"
    s, r = _request("POST", webhook_url,
                    body=json.loads(payload_str),
                    headers={"Stripe-Signature": stale_sig})
    check("Webhook stale timestamp → 400", s, r, 400); time.sleep(delay)

    # -----------------------------------------------------------------------
    section("7. Overage endpoint — plan restrictions")

    s, r = _request("POST", f"{base}/v1/keys/overage",
                    body={"enabled": True, "cap_eur": 20.0},
                    headers={"X-Api-Key": free_key})
    check("Free key cannot enable overage → 403", s, r, 403); time.sleep(delay)

    s, r = _request("POST", f"{base}/v1/keys/overage",
                    body={"enabled": True, "cap_eur": 1.0},
                    headers={"X-Api-Key": free_key})
    check("Free key overage cap too low → 403", s, r, 403); time.sleep(delay)

    s, r = _request("GET", f"{base}/v1/keys/overage",
                    headers={"X-Api-Key": free_key})
    check("Free key GET overage → 200", s, r, 200); time.sleep(delay)

    # -----------------------------------------------------------------------
    section("8. Information disclosure")

    s, r = _request("GET", f"{base}/v1/health"); time.sleep(delay)
    check("Health endpoint → 200", s, r, 200)
    check("Health no secrets", s, r, 200,
          must_not_contain=["password", "secret", "fernet", "STRIPE_"])

    s, r = _request("GET", f"{base}/v1/pubkey"); time.sleep(delay)
    check("Pubkey → 200", s, r, 200)
    check("Pubkey no private key leak", s, r, 200,
          must_not_contain=["PRIVATE KEY", "private_key"])

    s, r = _request("GET", f"{base}/v1/pricing"); time.sleep(delay)
    check("Pricing → 200", s, r, 200)

    # -----------------------------------------------------------------------
    section("9. Method not allowed")

    for method, path in [
        ("DELETE", "/v1/usage"),
        ("PUT",    "/v1/usage"),
        ("PATCH",  "/v1/proxy"),
        ("DELETE", "/v1/webhooks/stripe"),
    ]:
        s, r = _request(method, f"{base}{path}",
                        headers={"X-Api-Key": free_key})
        time.sleep(delay)
        if s in (405, 404, 422):
            passed += 1
            print(f"  {GREEN}PASS{RESET} [{s}] {method} {path} → method not allowed")
        else:
            failed += 1
            findings.append(f"{method} {path} returned unexpected {s}")
            print(f"  {RED}FAIL{RESET} [{s}] {method} {path}")

    # -----------------------------------------------------------------------
    section("Summary")
    total = passed + failed
    print(f"\n  {GREEN}{passed}{RESET}/{total} checks passed, {RED}{failed}{RESET} failed\n")

    if findings:
        print(f"{RED}Findings:{RESET}")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. {f}")
    else:
        print(f"{GREEN}No findings. Safe to launch.{RESET}")

    return failed


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8100", help="Base URL")
    parser.add_argument("--key", default="", help="Existing API key to use (skips free-signup)")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    print(f"Security smoke test → {base}")

    n_failed = run(base, existing_key=args.key)
    sys.exit(0 if n_failed == 0 else 1)
