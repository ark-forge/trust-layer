"""Concurrency tests — race conditions on credit debit and add operations."""

import threading
import pytest
from datetime import datetime, timezone

from trust_layer.credits import (
    add_credits,
    debit_credits,
    get_balance,
    InsufficientCredits,
)
from trust_layer.config import PROOF_PRICE, OVERAGE_CAP_MIN, PRO_OVERAGE_PRICE, RATE_LIMIT_PER_KEY_PER_DAY
import trust_layer.rate_limit as _rl_mod  # for patched RATE_LIMITS_FILE at runtime
from trust_layer.keys import create_api_key
from trust_layer.persistence import load_json, save_json


@pytest.fixture
def fresh_key():
    return create_api_key("cus_concurrent_test", "ref_concurrent", "concurrent@test.com", test_mode=True)


def test_parallel_debit_cannot_overdraw(fresh_key):
    """10 threads all try to debit simultaneously with balance for only 5 proofs.

    Exactly 5 should succeed and 5 should raise InsufficientCredits.
    The balance must never go negative.
    """
    initial = PROOF_PRICE * 5  # 0.50 EUR = 5 proofs
    add_credits(fresh_key, initial, "pi_concurrent_test")

    successes = []
    failures = []
    lock = threading.Lock()

    def try_debit(i):
        try:
            txn_id, new_balance = debit_credits(fresh_key, PROOF_PRICE, f"prf_concurrent_{i:03d}")
            with lock:
                successes.append((txn_id, new_balance))
        except InsufficientCredits:
            with lock:
                failures.append(i)

    threads = [threading.Thread(target=try_debit, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 5, f"Expected 5 successes, got {len(successes)}"
    assert len(failures) == 5, f"Expected 5 failures, got {len(failures)}"

    final_balance = get_balance(fresh_key)
    assert final_balance >= 0.0, f"Balance went negative: {final_balance}"
    assert final_balance == pytest.approx(0.0), f"Expected 0.0 balance, got {final_balance}"


def test_parallel_add_is_atomic(fresh_key):
    """10 threads each add 1.00 EUR simultaneously.

    Final balance must equal exactly 10.00 EUR (no lost updates).
    """
    results = []
    lock = threading.Lock()

    def try_add(i):
        new_balance = add_credits(fresh_key, 1.00, f"pi_add_{i:03d}")
        with lock:
            results.append(new_balance)

    threads = [threading.Thread(target=try_add, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final_balance = get_balance(fresh_key)
    assert final_balance == pytest.approx(10.00), f"Expected 10.00, got {final_balance}"


def test_mixed_debit_add_concurrent(fresh_key):
    """5 threads add, 5 threads debit simultaneously starting from 0.50 EUR.

    Balance must never go negative.
    """
    add_credits(fresh_key, PROOF_PRICE * 5, "pi_mixed_init")  # 0.50 EUR initial

    errors = []
    lock = threading.Lock()

    def try_debit(i):
        try:
            debit_credits(fresh_key, PROOF_PRICE, f"prf_mixed_{i:03d}")
        except InsufficientCredits:
            pass  # expected for some debits
        except Exception as e:
            with lock:
                errors.append(f"debit_{i}: {e}")

    def try_add(i):
        try:
            add_credits(fresh_key, 1.00, f"pi_mixed_{i:03d}")
        except Exception as e:
            with lock:
                errors.append(f"add_{i}: {e}")

    threads = (
        [threading.Thread(target=try_debit, args=(i,)) for i in range(5)]
        + [threading.Thread(target=try_add, args=(i,)) for i in range(5)]
    )
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Unexpected errors: {errors}"
    final_balance = get_balance(fresh_key)
    assert final_balance >= 0.0, f"Balance went negative: {final_balance}"


def test_concurrent_overage_at_cap_boundary():
    """Two threads simultaneously try to get overage when spent is 1 proof from cap.

    With cap=5.00 EUR and price=0.01 EUR, setting spent=4.99 leaves exactly
    1 overage slot. Both threads race — exactly one must succeed (is_overage=True),
    one must be blocked (reason='overage_cap'). The cap must never be exceeded.

    We exhaust the quota by pre-filling month_count to the real Pro limit (5 000)
    — no patching needed, which avoids inter-thread dict-mutation race conditions.
    """
    from trust_layer.rate_limit import check_rate_limit
    from trust_layer.keys import update_overage_settings
    from trust_layer.config import _PRO_MONTHLY_LIMIT

    key = create_api_key("cus_conc_ov", "ref_conc_ov", "conc_ov@test.com", plan="pro")
    add_credits(key, 5.0, "pi_conc_ov")
    update_overage_settings(key, enabled=True, cap_eur=OVERAGE_CAP_MIN, overage_rate=PRO_OVERAGE_PRICE)

    # IMPORTANT: use the patched RATE_LIMITS_FILE path (set by conftest monkeypatch on rl_mod)
    rl_rate_limits_file = _rl_mod.RATE_LIMITS_FILE

    # Pre-fill: quota FULLY exhausted (month_count = Pro monthly limit),
    # overage spent = cap - 1 proof → exactly 1 overage slot remains.
    key_id = key[:16]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    limits = load_json(rl_rate_limits_file, {})
    limits[key_id] = {
        "date": today, "count": 0,
        "month": month, "month_count": _PRO_MONTHLY_LIMIT,
        "overage_count": 499,
        "overage_spent_eur": round(OVERAGE_CAP_MIN - PRO_OVERAGE_PRICE, 4),  # 4.99
    }
    save_json(rl_rate_limits_file, limits)

    results = []
    results_lock = threading.Lock()

    def try_overage():
        allowed, remaining, is_overage, reason = check_rate_limit(key, limit=RATE_LIMIT_PER_KEY_PER_DAY)
        with results_lock:
            results.append((allowed, is_overage, reason))

    threads = [threading.Thread(target=try_overage) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one allowed (is_overage=True), one blocked (overage_cap)
    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]
    assert len(successes) == 1, f"Expected exactly 1 success, got {results}"
    assert len(failures) == 1, f"Expected exactly 1 failure, got {results}"
    assert successes[0][1] is True, f"Success must have is_overage=True, got {successes[0]}"
    assert failures[0][2] == "overage_cap", f"Failure must be overage_cap, got {failures[0]}"

    # Cap must not be exceeded
    final_limits = load_json(rl_rate_limits_file, {})
    entry = final_limits.get(key_id, {})
    assert round(entry.get("overage_spent_eur", 0), 4) <= OVERAGE_CAP_MIN
