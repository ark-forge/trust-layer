"""RFC 6962 Merkle tree — the primitive used at both the field and the batch level.

The cross-check against a real Sigstore inclusion proof is what makes this more
than a self-consistent implementation: Sigstore's tree was built by someone else,
so recomputing its root from a captured proof is an external witness that the
shape is right.
"""

import hashlib
import json
from pathlib import Path

import pytest

from trust_layer.merkle import (audit_path, expected_path_len, inclusion_root,
                                leaf_hash, merkle_root, node_hash)

FIXTURES = Path(__file__).parent / "fixtures" / "verify_proof"


def _leaves(n):
    return [leaf_hash(bytes([i])) for i in range(n)]


def test_single_leaf_root_is_the_leaf():
    """MTH({d0}) = leaf hash, not a node hash over a duplicated leaf."""
    leaves = _leaves(1)
    assert merkle_root(leaves) == leaves[0]
    assert audit_path(0, leaves) == []


def test_empty_tree_has_no_root():
    with pytest.raises(ValueError):
        merkle_root([])


def test_leaf_and_node_domains_are_separated():
    """Without the 0x00/0x01 prefixes an interior node replays as a leaf."""
    a, b = leaf_hash(b"a"), leaf_hash(b"b")
    assert node_hash(a, b) != hashlib.sha256(a + b).digest()
    assert leaf_hash(b"x") != hashlib.sha256(b"x").digest()


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 100])
def test_every_leaf_has_a_path_that_reaches_the_root(n):
    leaves = _leaves(n)
    root = merkle_root(leaves)
    for i in range(n):
        path = audit_path(i, leaves)
        computed, consumed = inclusion_root(leaves[i], i, n, path)
        assert computed == root
        assert consumed == len(path)


def test_odd_node_is_promoted_not_duplicated():
    """CVE-2012-2459: duplicating the last node makes two leaf sets share a root."""
    three = _leaves(3)
    four = three + [three[2]]
    assert merkle_root(three) != merkle_root(four)


def test_a_tampered_audit_path_does_not_reach_the_root():
    leaves = _leaves(7)
    root = merkle_root(leaves)
    path = audit_path(3, leaves)
    path[0] = bytes(32)
    computed, _ = inclusion_root(leaves[3], 3, 7, path)
    assert computed != root


def test_a_wrong_index_does_not_reach_the_root():
    leaves = _leaves(7)
    root = merkle_root(leaves)
    computed, _ = inclusion_root(leaves[3], 4, 7, audit_path(3, leaves))
    assert computed != root


def test_a_longer_path_than_the_tree_shape_leaves_siblings_unused():
    leaves = _leaves(7)
    path = audit_path(3, leaves) + [bytes(32)]
    computed, consumed = inclusion_root(leaves[3], 3, 7, path)
    assert computed == merkle_root(leaves)
    assert consumed < len(path)          # the caller must reject on this


def test_matches_a_real_sigstore_inclusion_proof():
    """External witness: recompute Sigstore's own root from a captured entry."""
    entry = json.loads((FIXTURES / "rekor_entry.json").read_text())
    body = next(iter(entry.values()))
    ip = body["verification"]["inclusionProof"]
    import base64
    leaf = leaf_hash(base64.b64decode(body["body"]))
    root, consumed = inclusion_root(leaf, ip["logIndex"], ip["treeSize"],
                                    [bytes.fromhex(h) for h in ip["hashes"]])
    assert root.hex() == ip["rootHash"]
    assert consumed == len(ip["hashes"])


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 100])
def test_expected_path_len_matches_the_paths_actually_built(n):
    leaves = _leaves(n)
    for i in range(n):
        assert expected_path_len(i, n) == len(audit_path(i, leaves))


def test_an_overstated_tree_size_needs_a_longer_path_than_the_real_one():
    """The case a walk alone accepts: with a bigger declared size, the same path
    reaches the real root and stops early. The length check is what refuses it."""
    leaves = _leaves(8)
    path = audit_path(0, leaves)
    computed, consumed = inclusion_root(leaves[0], 0, 4096, path)
    assert computed == merkle_root(leaves)        # the walk is fooled
    assert consumed == len(path)                  # and so is the consumed check
    assert expected_path_len(0, 4096) != len(path)  # the length is not
