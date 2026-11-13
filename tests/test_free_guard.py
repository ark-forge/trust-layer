"""TLGRAT: reversible free mode, shared caps, kill switch, aggregate measurement.

Every guard has a refusal test that checks the absent effect (nothing stored,
nothing sent, nothing charged), not only the status code.
"""

import contextlib
import json
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from fastapi.testclient import TestClient

SALT = "test-salt-not-from-the-repo"
INTERNAL_IP = "90.105.196.22"

PAID_ROUTES = [
    ("POST", "/v1/keys/setup"),
    ("POST", "/create-checkout-session"),
    ("GET", "/trial"),
    ("POST", "/v1/keys/trial"),
]


@pytest.fixture
def guard_redis(monkeypatch):
    """One fake Redis shared by the guard and the metrics modules."""
    client = fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)
    import trust_layer.free_tier_guard as guard_mod
    import trust_layer.usage_metrics as metrics_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: client)
    monkeypatch.setattr(metrics_mod, "get_redis", lambda: client)
    return client


@pytest.fixture(autouse=True)
def _guard_env(monkeypatch, guard_redis):
    for name in ("TL_PAID_PLANS_ENABLED", "TL_FREE_DAILY_GLOBAL_CAP", "TL_WRITES_PAUSED",
                 "TL_PROOF_EMAIL_DAILY_MAX"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TL_METRICS_SALT", SALT)


@pytest.fixture
def client():
    from trust_layer.app import app
    return TestClient(app)


@pytest.fixture
def free_key():
    from trust_layer.keys import create_api_key
    return create_api_key("", "free_guard", "free-guard@arkforge-test.dev", test_mode=False, plan="free")


@pytest.fixture
def pro_key():
    from trust_layer.keys import create_api_key
    return create_api_key("cus_guard", "sub_guard", "pro-guard@arkforge-test.dev", test_mode=False, plan="pro")


def _mock_http():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"result": "ok"}
    resp.headers = {}
    http = AsyncMock()
    http.post.return_value = resp
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=None)
    return http


def _prove(client, key, headers=None):
    with patch("httpx.AsyncClient", return_value=_mock_http()), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        return client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}", **(headers or {})},
        )


def _stored_proofs(tmp_path):
    return sorted((tmp_path / "proofs").glob("**/*.json"))


# --- 1. TL_PAID_PLANS_ENABLED ---

def test_flag_true_by_default_keeps_paid_routes_answering_as_before(client):
    # Invalid body: the handler itself answers 400, not the flag gate.
    r = client.post("/v1/keys/setup", json={"email": "not-an-email"})
    assert r.status_code == 400
    assert "pro" in client.get("/v1/pricing").json()["plans"]


@pytest.mark.parametrize("method,path", PAID_ROUTES)
def test_flag_false_paid_route_answers_410_and_calls_no_stripe(client, monkeypatch, method, path):
    monkeypatch.setenv("TL_PAID_PLANS_ENABLED", "false")
    stripe_mock = MagicMock()
    with patch("trust_layer.app.stripe", stripe_mock):
        r = client.request(method, path, json={"email": "someone@arkforge-test.dev"})
    assert r.status_code == 410
    assert "/v1/keys/free-signup" in json.dumps(r.json())
    assert stripe_mock.mock_calls == []


def test_flag_false_pricing_exposes_only_free_and_no_upgrade_cta(client, monkeypatch):
    monkeypatch.setenv("TL_PAID_PLANS_ENABLED", "false")
    body = client.get("/v1/pricing").json()
    assert list(body["plans"]) == ["free"]
    assert "upgrade_cta" not in json.dumps(body)


def test_flag_false_free_signup_response_has_no_upgrade_cta(client, monkeypatch):
    monkeypatch.setenv("TL_PAID_PLANS_ENABLED", "false")
    r = client.post("/v1/keys/free-signup", json={"email": "nocta@arkforge-test.dev"})
    assert r.status_code == 200
    assert "upgrade_cta" not in r.json()


def test_flag_true_free_signup_response_keeps_upgrade_cta(client):
    r = client.post("/v1/keys/free-signup", json={"email": "cta@arkforge-test.dev"})
    assert r.status_code == 200
    assert "upgrade_cta" in r.json()


def test_flag_false_stripe_webhook_still_processes_events(client, monkeypatch):
    monkeypatch.setenv("TL_PAID_PLANS_ENABLED", "false")
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_WEBHOOK_SECRET_TEST", "whsec_test_only")
    event = MagicMock()
    event.id = "evt_guard_1"
    event.type = "invoice.created"
    event.livemode = False
    event.data.object.to_dict.return_value = {}
    with patch("trust_layer.app.stripe.Webhook.construct_event", return_value=event):
        r = client.post("/v1/webhooks/stripe", content=b"{}", headers={"stripe-signature": "t=1,v1=x"})
    assert r.status_code == 200
    assert r.json() == {"received": True}


@pytest.mark.parametrize("raw,expected", [
    ("false", False), ("0", False), ("no", False), ("off", False), ("FALSE", False),
    ("true", True), ("1", True), ("", True),
])
def test_paid_plans_flag_parsing(monkeypatch, raw, expected):
    from trust_layer.free_tier_guard import paid_plans_enabled
    monkeypatch.setenv("TL_PAID_PLANS_ENABLED", raw)
    assert paid_plans_enabled() is expected


# --- 2. Global daily cap for free proofs ---

def test_free_proof_over_global_cap_is_429_and_nothing_is_stored(client, free_key, monkeypatch, tmp_path):
    monkeypatch.setenv("TL_FREE_DAILY_GLOBAL_CAP", "2")
    assert _prove(client, free_key).status_code == 200
    assert _prove(client, free_key).status_code == 200
    before = _stored_proofs(tmp_path)
    r = _prove(client, free_key)
    assert r.status_code == 429
    assert _stored_proofs(tmp_path) == before


def test_paid_key_passes_when_free_cap_is_reached(client, free_key, pro_key, monkeypatch):
    monkeypatch.setenv("TL_FREE_DAILY_GLOBAL_CAP", "1")
    assert _prove(client, free_key).status_code == 200
    assert _prove(client, free_key).status_code == 429
    assert _prove(client, pro_key).status_code == 200


def test_refused_proof_does_not_keep_a_slot(guard_redis, monkeypatch):
    from trust_layer.free_tier_guard import GuardError, release_free_proof, reserve_free_proof
    monkeypatch.setenv("TL_FREE_DAILY_GLOBAL_CAP", "1")
    slot = reserve_free_proof()
    with pytest.raises(GuardError):
        reserve_free_proof()
    release_free_proof(slot)
    reserve_free_proof()  # the slot freed by the release is usable, the refused one left no trace


def test_failed_write_gives_the_slot_back(client, free_key, monkeypatch, guard_redis):
    from trust_layer.free_tier_guard import _cap_key
    monkeypatch.setenv("TL_FREE_DAILY_GLOBAL_CAP", "1")
    with patch("trust_layer.proxy.store_proof", side_effect=OSError("disk full")), \
         patch("httpx.AsyncClient", return_value=_mock_http()), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock), pytest.raises(OSError):
        client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {free_key}"},
        )
    assert guard_redis.get(_cap_key()) == "0"
    assert _prove(client, free_key).status_code == 200


def test_unparseable_cap_refuses_free_writes(guard_redis, monkeypatch):
    from trust_layer.free_tier_guard import GuardError, reserve_free_proof
    monkeypatch.setenv("TL_FREE_DAILY_GLOBAL_CAP", "lots")
    with pytest.raises(GuardError) as exc:
        reserve_free_proof()
    assert exc.value.status == 503
    assert guard_redis.keys("*") == []


# --- 3. TL_WRITES_PAUSED kill switch ---

def test_kill_switch_env_refuses_free_write_with_503_and_stores_nothing(client, free_key, monkeypatch, tmp_path):
    monkeypatch.setenv("TL_WRITES_PAUSED", "1")
    r = _prove(client, free_key)
    assert r.status_code == 503
    assert _stored_proofs(tmp_path) == []


def test_kill_switch_redis_key_refuses_free_write(client, free_key, guard_redis, tmp_path):
    guard_redis.set("TL_WRITES_PAUSED", "1")
    r = _prove(client, free_key)
    assert r.status_code == 503
    assert _stored_proofs(tmp_path) == []
    assert guard_redis.keys("tl:free_cap:*") == []


def test_kill_switch_keeps_verification_of_existing_proof_at_200(client, free_key, monkeypatch):
    proof_id = _prove(client, free_key).json()["proof"]["proof_id"]
    monkeypatch.setenv("TL_WRITES_PAUSED", "1")
    assert client.get(f"/v1/proof/{proof_id}/verify").status_code == 200
    assert client.get(f"/v1/proof/{proof_id}").status_code == 200


def test_kill_switch_does_not_stop_paid_keys(client, pro_key, monkeypatch):
    monkeypatch.setenv("TL_WRITES_PAUSED", "1")
    assert _prove(client, pro_key).status_code == 200


def test_kill_switch_off_lets_free_write_through(client, free_key, monkeypatch):
    monkeypatch.setenv("TL_WRITES_PAUSED", "0")
    assert _prove(client, free_key).status_code == 200


# --- Redis unavailable / atomicity ---

def test_redis_unavailable_refuses_free_write_with_503_and_stores_nothing(client, free_key, monkeypatch, tmp_path):
    import trust_layer.free_tier_guard as guard_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: None)
    r = _prove(client, free_key)
    assert r.status_code == 503
    assert _stored_proofs(tmp_path) == []


def test_redis_erroring_refuses_free_write_with_503(client, free_key, monkeypatch, tmp_path):
    import trust_layer.free_tier_guard as guard_mod
    broken = MagicMock()
    broken.get.side_effect = ConnectionError("down")
    broken.pipeline.side_effect = ConnectionError("down")
    monkeypatch.setattr(guard_mod, "get_redis", lambda: broken)
    r = _prove(client, free_key)
    assert r.status_code == 503
    assert _stored_proofs(tmp_path) == []


def test_redis_unavailable_does_not_stop_paid_keys(client, pro_key, monkeypatch):
    import trust_layer.free_tier_guard as guard_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: None)
    assert _prove(client, pro_key).status_code == 200


def test_two_concurrent_requests_at_cap_minus_one_let_only_one_through(guard_redis, monkeypatch):
    from trust_layer.free_tier_guard import GuardError, reserve_free_proof
    monkeypatch.setenv("TL_FREE_DAILY_GLOBAL_CAP", "5")
    for _ in range(4):
        reserve_free_proof()
    barrier = threading.Barrier(2)
    outcomes = []

    def attempt():
        barrier.wait()
        try:
            reserve_free_proof()
            outcomes.append("ok")
        except GuardError as e:
            outcomes.append(e.status)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert sorted(map(str, outcomes)) == ["429", "ok"]
    # The refused request gave its increment back: the counter sits at the cap.
    from trust_layer.free_tier_guard import _cap_key
    assert guard_redis.get(_cap_key()) == "5"


# --- 4. One email per proof: daily cap per key ---

@pytest.mark.asyncio
async def test_email_n_plus_1_of_the_day_is_not_sent_but_proof_is_created(monkeypatch, guard_redis):
    from trust_layer import proxy as proxy_mod
    monkeypatch.setenv("TL_PROOF_EMAIL_DAILY_MAX", "2")
    sent = []
    monkeypatch.setattr(proxy_mod, "send_proof_email", lambda email, pid, rec: sent.append(pid))
    monkeypatch.setattr(proxy_mod, "add_proof_to_batch", lambda *a, **k: {"batch_id": "b"})
    record = {"parties": {"buyer_fingerprint": "fp_a"}}
    for n in range(3):
        await proxy_mod._post_proof_background(f"prf_{n}", record, "h", "https://v", "a@arkforge-test.dev", "free")
    assert sent == ["prf_0", "prf_1"]


@pytest.mark.asyncio
async def test_email_cap_is_per_key(monkeypatch, guard_redis):
    from trust_layer import proxy as proxy_mod
    monkeypatch.setenv("TL_PROOF_EMAIL_DAILY_MAX", "1")
    sent = []
    monkeypatch.setattr(proxy_mod, "send_proof_email", lambda email, pid, rec: sent.append(pid))
    monkeypatch.setattr(proxy_mod, "add_proof_to_batch", lambda *a, **k: {"batch_id": "b"})
    for fp in ("fp_a", "fp_b"):
        await proxy_mod._post_proof_background(
            f"prf_{fp}", {"parties": {"buyer_fingerprint": fp}}, "h", "https://v", "a@arkforge-test.dev", "free")
    assert sent == ["prf_fp_a", "prf_fp_b"]


@pytest.mark.asyncio
async def test_email_not_sent_when_redis_cannot_decide(monkeypatch):
    import trust_layer.free_tier_guard as guard_mod
    from trust_layer import proxy as proxy_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: None)
    sent = []
    monkeypatch.setattr(proxy_mod, "send_proof_email", lambda email, pid, rec: sent.append(pid))
    monkeypatch.setattr(proxy_mod, "add_proof_to_batch", lambda *a, **k: {"batch_id": "b"})
    await proxy_mod._post_proof_background(
        "prf_x", {"parties": {"buyer_fingerprint": "fp_a"}}, "h", "https://v", "a@arkforge-test.dev", "free")
    assert sent == []


# --- 5. Signup limit shared through Redis ---

def test_signup_limit_is_shared_between_nodes(client, guard_redis):
    import trust_layer.app as app_mod
    statuses = []
    for i in range(6):
        # Each request lands on a "fresh node": the per-process memory is empty.
        app_mod._FREE_SIGNUP_RATE.clear()
        statuses.append(client.post("/v1/keys/free-signup", json={"email": f"node{i}@arkforge-test.dev"}).status_code)
    assert statuses == [200] * 5 + [429]


def test_refused_signup_creates_no_key(client, guard_redis):
    import trust_layer.app as app_mod
    from trust_layer.keys import load_api_keys
    for i in range(5):
        client.post("/v1/keys/free-signup", json={"email": f"ok{i}@arkforge-test.dev"})
    app_mod._FREE_SIGNUP_RATE.clear()
    before = len(load_api_keys())
    r = client.post("/v1/keys/free-signup", json={"email": "refused@arkforge-test.dev"})
    assert r.status_code == 429
    assert len(load_api_keys()) == before


# --- 6. Aggregate measurement ---

def _metrics(client, monkeypatch, days=1):
    import trust_layer.routers.admin as admin_mod
    monkeypatch.setattr(admin_mod, "INTERNAL_SECRET", "admin-secret-test")
    return client.get(f"/v1/admin/metrics?days={days}", headers={"X-Internal-Secret": "admin-secret-test"})


def _today_row(response):
    return response.json()["days"][-1]


def test_signup_and_proof_increment_the_aggregates(client, monkeypatch):
    key = client.post("/v1/keys/free-signup", json={"email": "agg@arkforge-test.dev"}).json()["api_key"]
    assert _prove(client, key).status_code == 200
    row = _today_row(_metrics(client, monkeypatch))
    assert row["free_keys_created"] == 1
    assert row["proofs"] == 1
    assert row["active_keys"] == 1


def test_two_proofs_of_one_key_count_one_active_key(client, free_key, monkeypatch):
    _prove(client, free_key)
    _prove(client, free_key)
    row = _today_row(_metrics(client, monkeypatch))
    assert row["proofs"] == 2
    assert row["active_keys"] == 1


def test_external_verifications_are_counted(client, free_key, monkeypatch):
    proof_id = _prove(client, free_key).json()["proof"]["proof_id"]
    client.get(f"/v1/proof/{proof_id}")
    client.get(f"/v1/proof/{proof_id}/verify")
    assert _today_row(_metrics(client, monkeypatch))["external_verifications"] == 2


def test_internal_ip_is_not_counted(client, free_key, monkeypatch, guard_redis):
    proof_id = _prove(client, free_key).json()["proof"]["proof_id"]
    internal = {"x-real-ip": INTERNAL_IP}
    client.get(f"/v1/proof/{proof_id}", headers=internal)
    client.get(f"/v1/proof/{proof_id}/verify", headers=internal)
    client.post("/v1/keys/free-signup", json={"email": "internal@arkforge-test.dev"}, headers=internal)
    row = _today_row(_metrics(client, monkeypatch))
    assert row["external_verifications"] == 0
    assert row["free_keys_created"] == 0


def test_internal_key_proof_is_not_counted(client, monkeypatch):
    from trust_layer.keys import create_api_key
    key = create_api_key("", "internal_guard", "int@arkforge.tech", test_mode=False, plan="internal")
    assert _prove(client, key).status_code == 200
    row = _today_row(_metrics(client, monkeypatch))
    assert row["proofs"] == 0 and row["active_keys"] == 0


def test_serialized_aggregate_holds_no_ip_email_or_key(client, free_key, monkeypatch, guard_redis):
    email = "leak-check@arkforge-test.dev"
    ip = "203.0.113.77"
    key = client.post("/v1/keys/free-signup", json={"email": email}, headers={"x-real-ip": ip}).json()["api_key"]
    proof_id = _prove(client, key, headers={"x-real-ip": ip}).json()["proof"]["proof_id"]
    client.get(f"/v1/proof/{proof_id}", headers={"x-real-ip": ip})
    text = _metrics(client, monkeypatch).text
    for secret in (ip, email, "leak-check", "example.com", key, free_key, SALT):
        assert secret not in text
    # Nothing in Redis carries an identifier either: only counters and a sketch.
    for name in guard_redis.keys("tl:m:*"):
        assert ip not in name and email not in name and key not in name


def test_aggregate_exposes_totals_only_no_per_identifier_dimension(client, free_key, monkeypatch):
    _prove(client, free_key)
    body = _metrics(client, monkeypatch).json()
    allowed = {"date", "free_keys_created", "active_keys", "proofs", "external_verifications"}
    assert all(set(row) == allowed for row in body["days"])
    assert set(body) == {"days", "salt_configured"}


def test_metrics_endpoint_refuses_without_internal_secret(client, monkeypatch):
    import trust_layer.routers.admin as admin_mod
    monkeypatch.setattr(admin_mod, "INTERNAL_SECRET", "admin-secret-test")
    assert client.get("/v1/admin/metrics").status_code == 403
    assert client.get("/v1/admin/metrics", headers={"X-Internal-Secret": "wrong"}).status_code == 403


def test_metrics_endpoint_refuses_when_no_secret_is_configured(client, monkeypatch):
    import trust_layer.routers.admin as admin_mod
    monkeypatch.setattr(admin_mod, "INTERNAL_SECRET", "")
    assert client.get("/v1/admin/metrics", headers={"X-Internal-Secret": ""}).status_code == 403


def test_no_salt_means_no_active_key_sketch_and_no_identifier_stored(client, free_key, monkeypatch, guard_redis):
    monkeypatch.delenv("TL_METRICS_SALT", raising=False)
    _prove(client, free_key)
    assert all("active" not in name for name in guard_redis.keys("tl:m:*"))
    assert _today_row(_metrics(client, monkeypatch))["proofs"] == 1


# --- 7. Adjacent fixes ---

def test_get_proof_logs_no_raw_ip(client, free_key, caplog, tmp_path):
    proof_id = _prove(client, free_key).json()["proof"]["proof_id"]
    ip = "198.51.100.23"
    with caplog.at_level("DEBUG"):
        r = client.get(f"/v1/proof/{proof_id}", headers={"x-real-ip": ip})
    assert r.status_code == 200
    assert ip not in caplog.text
    access_log = (tmp_path / "data" / "proof_access_log.jsonl").read_text()
    assert ip not in access_log
    entry = json.loads(access_log.splitlines()[-1])
    assert entry["ip_hash"] and entry["ip_hash"] != ip


def test_get_proof_log_without_salt_holds_no_ip_either(client, free_key, monkeypatch, tmp_path):
    proof_id = _prove(client, free_key).json()["proof"]["proof_id"]
    monkeypatch.delenv("TL_METRICS_SALT", raising=False)
    ip = "198.51.100.24"
    client.get(f"/v1/proof/{proof_id}", headers={"x-real-ip": ip})
    assert ip not in (tmp_path / "data" / "proof_access_log.jsonl").read_text()


def test_hash_identifier_is_salted_and_stable(monkeypatch):
    from trust_layer.free_tier_guard import hash_identifier
    a = hash_identifier("203.0.113.1")
    assert a == hash_identifier("203.0.113.1")
    monkeypatch.setenv("TL_METRICS_SALT", "another-salt")
    assert hash_identifier("203.0.113.1") != a
    monkeypatch.delenv("TL_METRICS_SALT")
    assert hash_identifier("203.0.113.1") == ""


def test_email_hash_in_funnel_logs_has_no_fragment_of_the_email(client, tmp_path):
    email = "fragment@arkforge-test.dev"
    client.post("/v1/keys/free-signup", json={"email": email})
    seen = 0
    for name in ("conversion_events.jsonl", "funnel_events.jsonl"):
        path = tmp_path / "data" / name
        if not path.exists():
            continue
        text = path.read_text()
        hashes = [json.loads(line)["email_hash"] for line in text.splitlines()]
        assert "fra" not in json.dumps(hashes)
        assert "***" not in text
        assert hashes and all(len(h) >= 32 and h.isalnum() for h in hashes)
        seen += 1
    assert seen >= 1


def test_email_hash_helper_is_salted(monkeypatch):
    from trust_layer.app import _email_hash
    h = _email_hash("someone@arkforge-test.dev")
    assert h and "som" not in h and "@" not in h
    monkeypatch.setenv("TL_METRICS_SALT", "other-salt")
    assert _email_hash("someone@arkforge-test.dev") != h
    monkeypatch.delenv("TL_METRICS_SALT")
    assert _email_hash("someone@arkforge-test.dev") == ""


def test_metrics_endpoint_answers_503_when_counters_cannot_be_read(client, monkeypatch):
    import trust_layer.usage_metrics as metrics_mod
    monkeypatch.setattr(metrics_mod, "get_redis", lambda: None)
    assert _metrics(client, monkeypatch).status_code == 503


# --- Review round 1 ---

def test_no_salt_no_unsalted_ip_digest_in_any_redis_key(client, monkeypatch, guard_redis):
    import hashlib
    monkeypatch.delenv("TL_METRICS_SALT", raising=False)
    ip = "203.0.113.7"
    client.post("/api/register", json={"email": "nosalt@arkforge-test.dev"}, headers={"x-real-ip": ip})
    digest = hashlib.sha256(ip.encode()).hexdigest()
    keys = guard_redis.keys("*")
    assert not any(digest in k or ip in k for k in keys)
    assert not any(k.startswith("tl:signup_ip:") for k in keys)


def test_metrics_without_salt_says_so_instead_of_zero(client, monkeypatch):
    monkeypatch.delenv("TL_METRICS_SALT", raising=False)
    r = _metrics(client, monkeypatch)
    assert r.json()["salt_configured"] is False
    assert r.json()["days"][-1]["active_keys"] is None


@pytest.mark.asyncio
async def test_paid_key_email_is_not_capped_even_without_redis(monkeypatch):
    import trust_layer.free_tier_guard as guard_mod
    from trust_layer import proxy as proxy_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: None)
    sent = []
    monkeypatch.setattr(proxy_mod, "send_proof_email", lambda email, pid, rec: sent.append(pid))
    monkeypatch.setattr(proxy_mod, "add_proof_to_batch", lambda *a, **k: {"batch_id": "b"})
    await proxy_mod._post_proof_background(
        "prf_p", {"parties": {"buyer_fingerprint": "fp_p"}}, "h", "https://v", "a@arkforge-test.dev", "pro")
    assert sent == ["prf_p"]


def test_release_hits_the_day_of_the_reservation(guard_redis):
    from trust_layer.free_tier_guard import release_free_proof
    release_free_proof("tl:free_cap:19990101")
    # Never creates a day counter out of nothing but the one it was given, with a TTL.
    assert guard_redis.ttl("tl:free_cap:19990101") > 0


def test_failure_after_the_write_keeps_the_slot(client, free_key, monkeypatch, guard_redis):
    from trust_layer import proxy as proxy_mod
    from trust_layer.free_tier_guard import _cap_key
    monkeypatch.setattr(proxy_mod, "_cache_idempotency",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk")), raising=False)
    monkeypatch.setattr(proxy_mod, "_update_agent_profile",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk")), raising=False)
    with contextlib.suppress(Exception):
        _prove(client, free_key, {"X-Idempotency-Key": "idem-after-write"})
    assert guard_redis.get(_cap_key()) == "1"


def test_idempotent_replay_takes_no_slot(client, free_key, guard_redis):
    from trust_layer.free_tier_guard import _cap_key
    h = {"X-Idempotency-Key": "idem-replay-1"}
    assert _prove(client, free_key, h).status_code == 200
    assert _prove(client, free_key, h).status_code == 200
    assert guard_redis.get(_cap_key()) == "1"


def test_demo_obeys_the_kill_switch(client, monkeypatch):
    monkeypatch.setenv("TL_WRITES_PAUSED", "true")
    r = client.post("/v1/demo", json={"target": "https://example.com", "payload": {}})
    assert r.status_code == 503


def test_410_carries_cors_headers(client, monkeypatch):
    monkeypatch.setenv("TL_PAID_PLANS_ENABLED", "false")
    r = client.post("/create-checkout-session", json={}, headers={"Origin": "https://arkforge.tech"})
    assert r.status_code == 410
    assert "access-control-allow-origin" in r.headers
