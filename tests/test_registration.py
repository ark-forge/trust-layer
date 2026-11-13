"""TLREG: free API key delivered by email only, after the address is confirmed.

Every guard has a refusal test that checks the absent effect (no mail sent, no key
stored, no pending record kept), not only the status code.
"""

import json
import logging
import re
import smtplib
import threading
import time
from email import message_from_string

import fakeredis
import pytest
from fastapi.testclient import TestClient

from trust_layer.email_notify import _send_email as _real_send_email

SALT = "test-salt-not-from-the-repo"
SIGNUP = "/v1/keys/free-signup"
REGISTER = "/api/register"
BOTH = [SIGNUP, REGISTER]
CONFIRM = "/v1/register/confirm"
TOKEN_RE = re.compile(r"#token=([A-Za-z0-9_\-]+)")


@pytest.fixture
def reg_redis(monkeypatch):
    client = fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)
    import trust_layer.free_tier_guard as guard_mod
    import trust_layer.usage_metrics as metrics_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: client)
    monkeypatch.setattr(metrics_mod, "get_redis", lambda: client)
    return client


@pytest.fixture(autouse=True)
def _env(monkeypatch, reg_redis):
    for name in ("TL_REG_MAIL_DAILY_MAX", "TL_PAID_PLANS_ENABLED", "TL_WRITES_PAUSED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TL_METRICS_SALT", SALT)


@pytest.fixture
def client():
    from trust_layer.app import app
    return TestClient(app)


def _post(client, path, email, ip=None, **extra):
    headers = {"x-real-ip": ip} if ip else {}
    return client.post(path, json={"email": email, **extra}, headers=headers)


def _token(mail):
    return TOKEN_RE.search(mail["body"]).group(1)


def _keys():
    from trust_layer.keys import load_api_keys
    return load_api_keys()


def _free_keys_of(email):
    return [k for k, v in _keys().items() if v.get("email") == email and v.get("plan") == "free"]


def _pending(r):
    return r.keys("reg_pending:*")


def _events(tmp_path, name):
    path = tmp_path / "data" / name
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- 1. Response never carries a key, same shape for new and known addresses ---

@pytest.mark.parametrize("path", BOTH)
def test_request_answers_202_pending_without_api_key_for_new_and_known_address(client, mailbox, path):
    from trust_layer.keys import create_api_key
    create_api_key("", "known", "known@arkforge-test.dev", test_mode=False, plan="free")
    new = _post(client, path, "brand-new@arkforge-test.dev")
    known = _post(client, path, "known@arkforge-test.dev")
    assert new.status_code == known.status_code == 202
    assert new.json() == known.json()
    assert new.json()["status"] == "pending_confirmation"
    for r in (new, known):
        assert "api_key" not in r.text
        assert "arkforge-test.dev" not in r.text
    assert len(mailbox) == 2


@pytest.mark.parametrize("path", BOTH)
def test_honeypot_signup_gets_the_same_202_and_nothing_is_sent_or_stored(client, mailbox, reg_redis, path):
    r = _post(client, path, "bot@arkforge-test.dev", website="http://spam.invalid")
    assert r.status_code == 202
    assert r.json()["status"] == "pending_confirmation"
    assert mailbox == []
    assert _pending(reg_redis) == []


# --- 2. No key before confirm, exactly one after ---

@pytest.mark.parametrize("path", BOTH)
def test_no_key_exists_before_confirm_and_exactly_one_after(client, mailbox, path):
    email = "once@arkforge-test.dev"
    _post(client, path, email)
    assert _free_keys_of(email) == []
    assert all("Your API key" not in m["body"] for m in mailbox)
    r = client.post(CONFIRM, json={"token": _token(mailbox[0])})
    assert r.status_code == 200
    assert r.json() == {"status": "confirmed"}
    assert len(_free_keys_of(email)) == 1
    assert len(mailbox) == 2 and "Your API key" in mailbox[1]["body"]
    assert mailbox[1]["to"] == email


def test_confirm_for_a_known_address_resends_the_key_and_creates_no_second_key(client, mailbox):
    from trust_layer.keys import create_api_key
    key = create_api_key("", "known", "known@arkforge-test.dev", test_mode=False, plan="free")
    _post(client, SIGNUP, "known@arkforge-test.dev")
    r = client.post(CONFIRM, json={"token": _token(mailbox[0])})
    assert r.status_code == 200 and "api_key" not in r.text and key not in r.text
    assert _free_keys_of("known@arkforge-test.dev") == [key]
    assert key in mailbox[1]["body"]


# --- 3. Token: single use, 24h, no oracle; GET does not consume, POST does ---

def test_token_is_single_use(client, mailbox):
    _post(client, SIGNUP, "single@arkforge-test.dev")
    token = _token(mailbox[0])
    assert client.post(CONFIRM, json={"token": token}).status_code == 200
    second = client.post(CONFIRM, json={"token": token})
    assert second.status_code == 400
    assert len(_free_keys_of("single@arkforge-test.dev")) == 1
    assert len(mailbox) == 2


def test_token_expires_after_24_hours_and_no_key_is_created(client, mailbox, monkeypatch):
    import trust_layer.registration as registration
    _post(client, SIGNUP, "late@arkforge-test.dev")
    token = _token(mailbox[0])
    real = time.time()
    monkeypatch.setattr(registration, "_now", lambda: real + 24 * 3600 + 5)
    r = client.post(CONFIRM, json={"token": token})
    assert r.status_code == 400
    assert _free_keys_of("late@arkforge-test.dev") == []
    assert len(mailbox) == 1


def test_token_is_still_valid_just_before_24_hours(client, mailbox, monkeypatch):
    import trust_layer.registration as registration
    _post(client, SIGNUP, "justin@arkforge-test.dev")
    real = time.time()
    monkeypatch.setattr(registration, "_now", lambda: real + 24 * 3600 - 60)
    assert client.post(CONFIRM, json={"token": _token(mailbox[0])}).status_code == 200


def test_pending_record_has_a_24h_ttl_and_no_token_in_clear(client, mailbox, reg_redis):
    _post(client, SIGNUP, "ttl@arkforge-test.dev")
    (name,) = _pending(reg_redis)
    assert 0 < reg_redis.ttl(name) <= 24 * 3600
    assert _token(mailbox[0]) not in name
    assert _token(mailbox[0]) not in reg_redis.get(name)


@pytest.mark.parametrize("bad", ["", "x", "A" * 43, "A" * 5000, "../etc/passwd", None, 12])
def test_wrong_token_is_400_with_one_identical_body_and_creates_nothing(client, mailbox, bad):
    _post(client, SIGNUP, "victim@arkforge-test.dev")
    used = _token(mailbox[0])
    client.post(CONFIRM, json={"token": used})
    keys_before = _keys()
    answers = {client.post(CONFIRM, json={"token": bad}).text, client.post(CONFIRM, json={"token": used}).text}
    assert len(answers) == 1
    assert client.post(CONFIRM, json={"token": bad}).status_code == 400
    assert _keys() == keys_before


def test_confirm_with_a_non_json_body_is_400(client):
    assert client.post(CONFIRM, content=b"not json").status_code == 400


def test_get_confirm_does_not_consume_the_token_and_post_does(client, mailbox, reg_redis):
    _post(client, SIGNUP, "scanner@arkforge-test.dev")
    token = _token(mailbox[0])
    for url in (CONFIRM, f"{CONFIRM}?token={token}"):
        r = client.get(url)
        assert r.status_code == 200
        assert token not in r.text
    assert len(_pending(reg_redis)) == 1
    assert _free_keys_of("scanner@arkforge-test.dev") == []
    assert client.post(CONFIRM, json={"token": token}).status_code == 200
    assert _pending(reg_redis) == []


# --- 4. Two tokens of one address confirmed in parallel: one key ---

def test_two_tokens_of_one_address_confirmed_in_parallel_create_one_key(client, mailbox, monkeypatch):
    import trust_layer.keys as keys_mod
    email = "race@arkforge-test.dev"
    _post(client, SIGNUP, email)
    _post(client, REGISTER, email)
    tokens = [_token(m) for m in mailbox]
    assert len(set(tokens)) == 2

    real_load = keys_mod.load_api_keys

    def slow_load():
        data = real_load()
        time.sleep(0.05)  # widen the window between the read and the write
        return data

    monkeypatch.setattr(keys_mod, "load_api_keys", slow_load)
    from trust_layer.app import app
    statuses = []

    def confirm(tok):
        statuses.append(TestClient(app).post(CONFIRM, json={"token": tok}).status_code)

    threads = [threading.Thread(target=confirm, args=(t,)) for t in tokens]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    monkeypatch.setattr(keys_mod, "load_api_keys", real_load)
    assert statuses == [200, 200]
    assert len(_free_keys_of(email)) == 1


def test_get_or_create_free_key_returns_the_existing_key(client):
    from trust_layer.keys import get_or_create_free_key
    key, created = get_or_create_free_key("goc@arkforge-test.dev", "ref")
    again, created_again = get_or_create_free_key("GOC@arkforge-test.dev", "ref")
    assert created is True and created_again is False and again == key


# --- 5. Per-address cap, per-IP cap, daily mail cap ---

@pytest.mark.parametrize("path", BOTH)
def test_fourth_request_for_one_address_gets_the_same_202_and_sends_no_mail(client, mailbox, reg_redis, path):
    import trust_layer.registration as registration
    n = registration.ADDRESS_MAX_PER_DAY
    answers = []
    for _ in range(n + 2):
        r = _post(client, path, "spammed@arkforge-test.dev")
        answers.append((r.status_code, r.text))
    assert len(set(answers)) == 1 and answers[0][0] == 202
    assert len(mailbox) == n
    assert len(_pending(reg_redis)) == n


def test_address_cap_counts_the_two_endpoints_together_and_ignores_case(client, mailbox):
    for path, email in [(SIGNUP, "Mix@arkforge-test.dev"), (REGISTER, "mix@arkforge-test.dev"),
                        (SIGNUP, "MIX@arkforge-test.dev"), (REGISTER, "mix@arkforge-test.dev")]:
        assert _post(client, path, email).status_code == 202
    assert len(mailbox) == 3


def test_address_cap_does_not_block_another_address(client, mailbox):
    for i in range(5):
        _post(client, SIGNUP, "noisy@arkforge-test.dev", ip=f"198.51.100.{i}")
    before = len(mailbox)
    assert _post(client, SIGNUP, "quiet@arkforge-test.dev").status_code == 202
    assert len(mailbox) == before + 1


def test_address_counter_is_salted_and_holds_no_address(client, mailbox, reg_redis):
    _post(client, SIGNUP, "hidden@arkforge-test.dev")
    names = reg_redis.keys("tl:reg_addr:*")
    assert len(names) == 1 and "hidden" not in names[0] and "arkforge-test" not in names[0]
    assert reg_redis.ttl(names[0]) > 0


def test_address_window_is_not_extended_by_blocked_requests(client, mailbox, reg_redis):
    for _ in range(3):
        _post(client, SIGNUP, "fixed@arkforge-test.dev")
    (name,) = reg_redis.keys("tl:reg_addr:*")
    reg_redis.expire(name, 100)
    _post(client, SIGNUP, "fixed@arkforge-test.dev")
    assert reg_redis.ttl(name) <= 100


def test_ip_limit_is_shared_refuses_with_429_and_sends_nothing(client, mailbox, reg_redis):
    import trust_layer.registration as registration
    n = registration.REQUEST_MAX_PER_IP_PER_HOUR
    ip = "203.0.113.9"
    for i in range(n):
        assert _post(client, SIGNUP if i % 2 else REGISTER, f"u{i}@arkforge-test.dev", ip=ip).status_code == 202
    sent, pending = len(mailbox), len(_pending(reg_redis))
    r = _post(client, SIGNUP, "one-more@arkforge-test.dev", ip=ip)
    assert r.status_code == 429
    assert len(mailbox) == sent and len(_pending(reg_redis)) == pending
    assert _post(client, SIGNUP, "other-ip@arkforge-test.dev", ip="203.0.113.10").status_code == 202


def test_ip_counter_lives_in_redis_under_a_salted_key(client, mailbox, reg_redis):
    ip = "203.0.113.11"
    _post(client, SIGNUP, "iphash@arkforge-test.dev", ip=ip)
    names = [k for k in reg_redis.keys("*") if ip in k]
    assert names == []
    assert reg_redis.keys("tl:signup_ip:*")


def test_daily_mail_cap_refuses_with_503_and_sends_nothing_more(client, mailbox, reg_redis, monkeypatch):
    monkeypatch.setenv("TL_REG_MAIL_DAILY_MAX", "2")
    assert _post(client, SIGNUP, "cap1@arkforge-test.dev").status_code == 202
    assert _post(client, REGISTER, "cap2@arkforge-test.dev").status_code == 202
    r = _post(client, SIGNUP, "cap3@arkforge-test.dev")
    assert r.status_code == 503
    assert len(mailbox) == 2 and len(_pending(reg_redis)) == 2


def test_unparseable_daily_mail_cap_refuses_with_503(client, mailbox, reg_redis, monkeypatch):
    monkeypatch.setenv("TL_REG_MAIL_DAILY_MAX", "lots")
    assert _post(client, SIGNUP, "badcap@arkforge-test.dev").status_code == 503
    assert mailbox == [] and _pending(reg_redis) == []


def test_address_over_its_cap_does_not_consume_the_daily_mail_cap(client, mailbox, monkeypatch):
    monkeypatch.setenv("TL_REG_MAIL_DAILY_MAX", "4")
    for i in range(6):
        _post(client, SIGNUP, "same@arkforge-test.dev", ip=f"198.51.100.{i}")
    assert len(mailbox) == 3
    assert _post(client, SIGNUP, "fresh@arkforge-test.dev").status_code == 202


def test_confirm_post_is_rate_limited_per_ip_and_keeps_the_token(client, mailbox, reg_redis):
    import trust_layer.registration as registration
    _post(client, SIGNUP, "brute@arkforge-test.dev")
    token = _token(mailbox[0])
    ip = {"x-real-ip": "203.0.113.20"}
    for i in range(registration.CONFIRM_MAX_PER_IP_PER_HOUR):
        assert client.post(CONFIRM, json={"token": f"wrong{i}"}, headers=ip).status_code == 400
    r = client.post(CONFIRM, json={"token": token}, headers=ip)
    assert r.status_code == 429
    assert _free_keys_of("brute@arkforge-test.dev") == []
    assert len(mailbox) == 1
    assert len(_pending(reg_redis)) == 1
    assert client.post(CONFIRM, json={"token": token}, headers={"x-real-ip": "203.0.113.21"}).status_code == 200


# --- 6. Fail closed ---

@pytest.mark.parametrize("path", BOTH)
def test_no_redis_is_503_with_no_mail_and_no_key(client, mailbox, monkeypatch, path):
    import trust_layer.free_tier_guard as guard_mod
    monkeypatch.setattr(guard_mod, "get_redis", lambda: None)
    r = _post(client, path, "noredis@arkforge-test.dev")
    assert r.status_code == 503
    assert mailbox == []
    assert _free_keys_of("noredis@arkforge-test.dev") == []


@pytest.mark.parametrize("path", BOTH)
def test_no_salt_is_503_with_no_mail_no_key_and_nothing_in_redis(client, mailbox, reg_redis, monkeypatch, path):
    monkeypatch.delenv("TL_METRICS_SALT")
    r = _post(client, path, "nosalt@arkforge-test.dev")
    assert r.status_code == 503
    assert mailbox == []
    assert _free_keys_of("nosalt@arkforge-test.dev") == []
    assert reg_redis.keys("*") == []


def test_erroring_redis_is_503_with_no_mail_and_no_key(client, mailbox, monkeypatch):
    import trust_layer.free_tier_guard as guard_mod

    class Broken:
        def __getattr__(self, name):
            def boom(*a, **k):
                raise ConnectionError("redis down")
            return boom

    monkeypatch.setattr(guard_mod, "get_redis", lambda: Broken())
    r = _post(client, SIGNUP, "broken@arkforge-test.dev")
    assert r.status_code == 503
    assert mailbox == [] and _free_keys_of("broken@arkforge-test.dev") == []


def test_confirm_without_redis_is_503_and_creates_no_key(client, mailbox, monkeypatch):
    import trust_layer.free_tier_guard as guard_mod
    _post(client, SIGNUP, "later@arkforge-test.dev")
    token = _token(mailbox[0])
    real = guard_mod.get_redis
    monkeypatch.setattr(guard_mod, "get_redis", lambda: None)
    assert client.post(CONFIRM, json={"token": token}).status_code == 503
    assert _free_keys_of("later@arkforge-test.dev") == [] and len(mailbox) == 1
    monkeypatch.setattr(guard_mod, "get_redis", real)
    assert client.post(CONFIRM, json={"token": token}).status_code == 200


def test_confirm_without_salt_is_503_and_creates_no_key(client, mailbox, monkeypatch):
    _post(client, SIGNUP, "nosaltc@arkforge-test.dev")
    token = _token(mailbox[0])
    monkeypatch.delenv("TL_METRICS_SALT")
    assert client.post(CONFIRM, json={"token": token}).status_code == 503
    assert _free_keys_of("nosaltc@arkforge-test.dev") == [] and len(mailbox) == 1


def test_confirm_blocked_in_failover_keeps_the_token(client, mailbox, monkeypatch):
    import trust_layer.app as app_mod
    _post(client, SIGNUP, "failover@arkforge-test.dev")
    token = _token(mailbox[0])
    monkeypatch.setattr(app_mod, "_writes_blocked", lambda: True)
    assert client.post(CONFIRM, json={"token": token}).status_code == 503
    assert _free_keys_of("failover@arkforge-test.dev") == []
    monkeypatch.setattr(app_mod, "_writes_blocked", lambda: False)
    assert client.post(CONFIRM, json={"token": token}).status_code == 200


def test_key_creation_failure_at_confirm_gives_the_token_back(client, mailbox, monkeypatch):
    import trust_layer.registration as registration
    _post(client, SIGNUP, "boom@arkforge-test.dev")
    token = _token(mailbox[0])

    def boom(*a, **k):
        raise OSError("disk full")

    real = registration.get_or_create_free_key
    monkeypatch.setattr(registration, "get_or_create_free_key", boom)
    assert client.post(CONFIRM, json={"token": token}).status_code == 503
    assert _free_keys_of("boom@arkforge-test.dev") == []
    monkeypatch.setattr(registration, "get_or_create_free_key", real)
    assert client.post(CONFIRM, json={"token": token}).status_code == 200
    assert len(_free_keys_of("boom@arkforge-test.dev")) == 1


# --- validation stays in front ---

@pytest.mark.parametrize("path", BOTH)
def test_invalid_address_is_400_and_nothing_is_stored_or_sent(client, mailbox, reg_redis, path):
    assert _post(client, path, "not-an-email").status_code == 400
    assert client.post(path, content=b"nope").status_code == 400
    assert mailbox == [] and _pending(reg_redis) == []


def test_blocked_disposable_domain_is_refused_by_free_signup_and_sends_nothing(client, mailbox, reg_redis):
    assert _post(client, SIGNUP, "x@mailinator.com").status_code == 422
    assert mailbox == [] and _pending(reg_redis) == []


# --- 7. No clear address or token in logs ---

class _FakeSMTP:
    """Stand-in for smtplib.SMTP_SSL: context manager with login() and sendmail()."""

    sent: list = []
    refuse = False

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def login(self, *a):
        pass

    def sendmail(self, sender, to, message):
        if _FakeSMTP.refuse:
            raise smtplib.SMTPRecipientsRefused({to: (550, b"mailbox unavailable")})
        _FakeSMTP.sent.append((to, message))


@pytest.fixture
def real_smtp(monkeypatch):
    import trust_layer.email_notify as email_mod
    _FakeSMTP.sent = []
    _FakeSMTP.refuse = False
    monkeypatch.setattr(email_mod, "_send_email", _real_send_email)
    monkeypatch.setattr(email_mod, "SMTP_PASSWORD", "not-a-real-password")
    monkeypatch.setattr(email_mod.smtplib, "SMTP_SSL", _FakeSMTP)
    return _FakeSMTP


def _assert_no_leak(text, *needles):
    for needle in needles:
        assert needle not in text


@pytest.mark.parametrize("path", BOTH)
def test_full_flow_logs_no_address_and_no_token(client, real_smtp, caplog, path):
    email = "private.person@arkforge-test.dev"
    with caplog.at_level(logging.DEBUG):
        _post(client, path, email, ip="203.0.113.30")
        (to, message), = real_smtp.sent
        assert to == email
        body = message_from_string(message).get_payload(0).get_payload(decode=True).decode()
        token = TOKEN_RE.search(body).group(1)
        client.post(CONFIRM, json={"token": "wrong-token-value"})
        assert client.post(CONFIRM, json={"token": token}).status_code == 200
        for _ in range(4):
            _post(client, path, email, ip="203.0.113.30")
    _assert_no_leak(caplog.text, email, "private.person", "arkforge-test.dev", token, "wrong-token-value")


def test_smtp_refusal_logs_no_address(client, real_smtp, caplog):
    real_smtp.refuse = True
    email = "refused.person@arkforge-test.dev"
    with caplog.at_level(logging.DEBUG):
        r = _post(client, SIGNUP, email)
    assert r.status_code == 202
    assert any(rec.levelno >= logging.ERROR for rec in caplog.records)
    _assert_no_leak(caplog.text, email, "refused.person", "arkforge-test.dev")


def test_skipped_test_address_logs_neither_address_nor_local_part(client, real_smtp, caplog):
    email = "smoke_leaky@arkforge.tech"
    with caplog.at_level(logging.DEBUG):
        _post(client, REGISTER, email)
    assert real_smtp.sent == []
    assert "skipped" in caplog.text.lower()
    _assert_no_leak(caplog.text, email, "smoke_leaky", "arkforge.tech")


def test_no_address_in_the_pending_record_key_or_in_funnel_logs(client, mailbox, reg_redis, tmp_path):
    email = "funnel.person@arkforge-test.dev"
    _post(client, SIGNUP, email)
    client.post(CONFIRM, json={"token": _token(mailbox[0])})
    for name in ("funnel_events.jsonl", "conversion_events.jsonl"):
        path = tmp_path / "data" / name
        text = path.read_text() if path.exists() else ""
        _assert_no_leak(text, email, "funnel.person")
    assert all(email not in k for k in reg_redis.keys("*"))


# --- 8. Token in the fragment only ---

def test_mail_carries_the_token_in_the_fragment_never_in_a_query_string(client, mailbox):
    _post(client, SIGNUP, "frag@arkforge-test.dev")
    body = mailbox[0]["body"]
    assert "/v1/register/confirm#token=" in body
    assert "?token=" not in body and "&token=" not in body
    assert "https://test.arkforge.fr/v1/register/confirm#token=" in body


def test_confirmation_page_reads_the_fragment_and_posts_the_token(client):
    html = client.get(CONFIRM).text
    assert "location.hash" in html
    assert "location.search" not in html
    assert "fetch(" in html and "POST" in html
    assert "history.replaceState" in html


def test_confirmation_page_does_not_leak_the_referrer(client):
    r = client.get(CONFIRM)
    assert "no-referrer" in r.text or r.headers.get("referrer-policy") == "no-referrer"
    assert "no-store" in r.headers.get("cache-control", "")


# --- 9. Funnel events move to the confirm step ---

def test_funnel_requested_at_request_completion_and_attribution_only_at_confirm(client, mailbox, tmp_path):
    email = "events@arkforge-test.dev"
    _post(client, REGISTER, email, source="web_register", scan_id="asr_1")
    funnel = [e["event"] for e in _events(tmp_path, "funnel_events.jsonl")]
    assert funnel == ["register_requested"]
    assert _events(tmp_path, "conversion_events.jsonl") == []
    client.post(CONFIRM, json={"token": _token(mailbox[0])})
    funnel = _events(tmp_path, "funnel_events.jsonl")
    assert [e["event"] for e in funnel] == ["register_requested", "register_completion"]
    assert funnel[1]["source"] == "web_register" and funnel[1]["scan_id"] == "asr_1"
    conversions = _events(tmp_path, "conversion_events.jsonl")
    assert [e["event"] for e in conversions] == ["signup_attributed"]
    assert conversions[0]["source"] == "web_register"


def test_known_address_confirm_emits_no_completion_and_counts_no_new_key(client, mailbox, tmp_path):
    from trust_layer.keys import create_api_key
    create_api_key("", "known", "known@arkforge-test.dev", test_mode=False, plan="free")
    _post(client, REGISTER, "known@arkforge-test.dev")
    client.post(CONFIRM, json={"token": _token(mailbox[0])})
    assert "register_completion" not in [e["event"] for e in _events(tmp_path, "funnel_events.jsonl")]
    assert _events(tmp_path, "conversion_events.jsonl") == []


def test_free_key_metric_counts_at_confirm_not_at_request(client, mailbox, reg_redis):
    from datetime import UTC, datetime
    name = f"tl:m:{datetime.now(UTC).strftime('%Y-%m-%d')}:free_keys_created"
    _post(client, SIGNUP, "metric@arkforge-test.dev")
    assert reg_redis.get(name) is None
    client.post(CONFIRM, json={"token": _token(mailbox[0])})
    assert reg_redis.get(name) == "1"


# --- web form ---

def test_register_page_no_longer_expects_a_key_in_the_response(client):
    html = client.get("/register").text
    assert "d.api_key" not in html
    assert "confirm" in html.lower()
