"""Concurrency tests — race conditions on credit debit and add operations."""

import threading
import pytest

from trust_layer.credits import (
    add_credits,
    debit_credits,
    get_balance,
    InsufficientCredits,
)
from trust_layer.config import PROOF_PRICE
from trust_layer.keys import create_api_key


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
