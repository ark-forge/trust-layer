"""Tests for API key lifecycle."""

from trust_layer.keys import (
    generate_api_key,
    validate_api_key,
    create_api_key,
    deactivate_key_by_ref,
    find_key_by_ref,
    is_test_key,
    is_free_key,
    is_enterprise_key,
    is_internal_key,
    get_key_plan,
    load_api_keys,
)


def test_generate_test_key():
    key = generate_api_key(test_mode=True)
    assert key.startswith("mcp_test_")
    assert len(key) == 9 + 48  # prefix + 24 bytes hex


def test_generate_live_key():
    key = generate_api_key(test_mode=False)
    assert key.startswith("mcp_pro_")


def test_create_and_validate():
    key = create_api_key("cus_123", "ref_123", "test@test.com", test_mode=True)
    info = validate_api_key(key)
    assert info is not None
    assert info["active"] is True
    assert info["stripe_customer_id"] == "cus_123"
    assert info["email"] == "test@test.com"


def test_validate_nonexistent():
    assert validate_api_key("mcp_test_nonexistent") is None


def test_deactivate_by_ref():
    key = create_api_key("cus_456", "ref_456", "x@x.com", test_mode=True)
    assert validate_api_key(key) is not None

    deactivate_key_by_ref("ref_456")
    assert validate_api_key(key) is None


def test_find_key_by_ref():
    key = create_api_key("cus_789", "ref_789", "y@y.com", test_mode=False)
    found = find_key_by_ref("ref_789")
    assert found == key

    assert find_key_by_ref("ref_nonexistent") is None


def test_is_test_key():
    assert is_test_key("mcp_test_abc123") is True
    assert is_test_key("mcp_pro_abc123") is False
    assert is_test_key("invalid") is False


def test_prefix_routing():
    test_key = generate_api_key(test_mode=True)
    live_key = generate_api_key(test_mode=False)
    assert is_test_key(test_key) is True
    assert is_test_key(live_key) is False


# --- Enterprise plan ---

def test_generate_enterprise_key():
    key = generate_api_key(plan="enterprise")
    assert key.startswith("mcp_ent_")
    assert len(key) == 8 + 48  # "mcp_ent_" (8) + 24 bytes hex (48)


def test_is_enterprise_key():
    assert is_enterprise_key("mcp_ent_abc123") is True
    assert is_enterprise_key("mcp_pro_abc123") is False
    assert is_enterprise_key("mcp_free_abc123") is False
    assert is_enterprise_key("mcp_test_abc123") is False


def test_is_free_key():
    assert is_free_key("mcp_free_abc123") is True
    assert is_free_key("mcp_pro_abc123") is False
    assert is_free_key("mcp_ent_abc123") is False


def test_get_key_plan_all_prefixes():
    assert get_key_plan("mcp_free_xxx") == "free"
    assert get_key_plan("mcp_pro_xxx") == "pro"
    assert get_key_plan("mcp_ent_xxx") == "enterprise"
    assert get_key_plan("mcp_test_xxx") == "test"
    assert get_key_plan("mcp_unknown_xxx") == "pro"  # fallback


def test_enterprise_key_test_mode_ignored():
    """test_mode=True is overridden by plan='enterprise'."""
    key = generate_api_key(test_mode=True, plan="enterprise")
    assert key.startswith("mcp_ent_")


def test_create_enterprise_key():
    key = create_api_key("cus_ent1", "ref_ent1", "ent@company.com", plan="enterprise")
    info = validate_api_key(key)
    assert info is not None
    assert info["plan"] == "enterprise"
    assert is_enterprise_key(key)


# --- Internal plan ---

def test_generate_internal_key():
    key = generate_api_key(plan="internal")
    assert key.startswith("mcp_int_")
    assert len(key) == 8 + 48  # "mcp_int_" (8) + 24 bytes hex (48)


def test_is_internal_key():
    assert is_internal_key("mcp_int_abc123") is True
    assert is_internal_key("mcp_pro_abc123") is False
    assert is_internal_key("mcp_free_abc123") is False
    assert is_internal_key("mcp_test_abc123") is False


def test_get_key_plan_internal():
    assert get_key_plan("mcp_int_xxx") == "internal"


def test_create_internal_key():
    key = create_api_key("internal_ceo", "internal_ceo", email="", plan="internal")
    info = validate_api_key(key)
    assert info is not None
    assert info["plan"] == "internal"
    assert is_internal_key(key)
