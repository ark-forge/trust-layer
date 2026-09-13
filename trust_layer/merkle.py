"""RFC 6962 Merkle tree — the single implementation used at both levels.

Two levels, one primitive:

  - field level : the per-field commitments of one proof hash into the proof's
                  chain hash (``trust_layer.commitments``).
  - batch level : the chain hashes of many proofs hash into one batch root,
                  which is what gets anchored (``trust_layer.batch_anchor``).

RFC 6962 rather than the naive tree, for three reasons that are security bugs
elsewhere:

  - leaf/node domain separation (``0x00`` / ``0x01``): without it an internal
    node can be replayed as a leaf.
  - odd node promoted, never duplicated: duplicating the last node (the Bitcoin
    shape, CVE-2012-2459) lets two different leaf sets produce the same root.
  - single-leaf root is defined as ``MTH({d0}) = sha256(0x00 || d0)``; the empty
    tree has no root and is never anchored.

``inclusion_root`` is the same walk ``trust_layer.rekor`` runs against Sigstore's
own inclusion proofs, so a third party reuses one routine for both.
"""

import hashlib
from typing import List, Sequence, Tuple


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: sha256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: sha256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest k such that k < n and k is a power of two (RFC 6962 split point)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash of already-hashed leaves (RFC 6962 section 2.1).

    ``leaves`` holds leaf hashes, not raw data: callers pass ``leaf_hash(x)``.
    Raises ValueError on an empty list — an empty batch has no root to anchor.
    """
    if not leaves:
        raise ValueError("merkle_root: empty tree has no root")
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_below(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """Inclusion proof for ``leaves[index]`` (RFC 6962 section 2.1.1)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError(f"audit_path: index {index} out of range for {n} leaves")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return audit_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return audit_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def expected_path_len(index: int, size: int) -> int:
    """How many siblings an inclusion proof for (index, size) must carry.

    Deterministic in RFC 6962, so a proof whose path is shorter or longer than
    this does not describe the tree it claims. Checking the length is what
    catches an overstated ``tree_size``: the walk alone would consume the real
    siblings, reach the real root and stop early, reporting a valid inclusion
    for a tree shape that never existed.
    """
    n, idx, sz = 0, index, size
    while sz > 1:
        if idx % 2 == 1 or idx + 1 < sz:
            n += 1
        idx //= 2
        sz = (sz + 1) // 2
    return n


def inclusion_root(leaf: bytes, index: int, size: int, path: Sequence[bytes]) -> Tuple[bytes, int]:
    """Walk an inclusion proof. Returns (root, siblings_consumed).

    A right-edge node is promoted without consuming a sibling, so the walk ends on
    tree size rather than on path exhaustion. The caller checks that every sibling
    was used: a leftover one means the proof does not match the shape walked.
    """
    h = leaf
    idx, sz, i = index, size, 0
    while sz > 1:
        if i >= len(path):
            return h, i  # short path — caller sees consumed < len(path) is False and root mismatches
        if idx % 2 == 1:
            h = node_hash(path[i], h)
            i += 1
        elif idx + 1 < sz:
            h = node_hash(h, path[i])
            i += 1
        idx //= 2
        sz = (sz + 1) // 2
    return h, i
