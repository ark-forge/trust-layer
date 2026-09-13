#!/usr/bin/env python3
"""Verify an ArkForge Trust Layer proof WITHOUT trusting ArkForge.

Standalone: Python 3.8+ standard library and the `openssl` binary. No pip install,
no rekor-cli, no cosign. A disputing party must be able to run this on a plain
machine, so the dependency floor is deliberately low.

    python3 verify_proof.py prf_20260303_161853_4d0904
    python3 verify_proof.py --file proof.json
    python3 verify_proof.py --offline --file proof.json       # skip network witnesses
    python3 verify_proof.py --file proof.json --disclose d.json  # check disclosed fields

What it checks, witness by witness:

  1. Chain hash        — recomputed from the proof's own fields. This only proves
                         internal consistency. On its own it is NOT evidence:
                         whoever fabricates a proof produces coherent hashes.
  2. Ed25519 signature — ArkForge's own signature over the chain hash, checked
                         against the key published at /.well-known/did.json.
                         Proves ArkForge issued it. Still not independent.
  3. Batch anchor      — the chain hash is a leaf of the batch Merkle tree whose
                         root was anchored. Self-consistency again, but it is what
                         carries witnesses 4 and 5 down to this individual proof.
  4. RFC 3161          — a third-party Timestamp Authority signed the anchored
                         hash at a point in time. INDEPENDENT of ArkForge.
  5. Sigstore Rekor    — the anchored hash is in a public append-only log, with an
                         inclusion proof against a signed checkpoint.
                         INDEPENDENT of ArkForge.

Only 4 and 5 are witnesses ArkForge cannot forge. Exit code is 0 only if every
applicable check passes.

Spec 3.0 and selective disclosure
---------------------------------
From spec 3.0 the chain hash is the Merkle root of one commitment per field,
``sha256(field || 0x00 || nonce || canonical_json(value))``. A third party
recomputes it from the published commitments alone — no field value is needed,
and none is exposed. That is what makes the anchored hash verifiable from the
public proof, which it was not before.

The proof owner can open any subset of fields out of band by handing over a JSON
file of ``(field, nonce, value)`` triplets::

    {"disclosed": {"seller": {"nonce": "<64 hex>", "value": "api.example.com"}}}

Pass it with ``--disclose``. Each triplet is checked against the published
commitment, so a disclosed value is provably the one that was anchored — while
every undisclosed field stays hidden behind its own independent nonce.
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# Overridable so the procedure can be run verbatim against another instance —
# a staging deployment, or a local one when measuring the verifier itself.
TRUST_LAYER_BASE = os.environ.get("TRUST_LAYER_BASE", "https://trust.arkforge.tech")
REKOR_BASE = "https://rekor.sigstore.dev"

# provider -> how to obtain the CA material that verifies its timestamp tokens.
#   "url"    : self-signed root not present in any OS trust store, fetched from the TSA.
#   "system" : public WebTrust CA, already in the system trust store; the token
#              carries its own chain, so no extra material is needed.
TSA_CA_SOURCES = {
    "freetsa.org": {"kind": "url",
                    "ca": "https://freetsa.org/files/cacert.pem",
                    "untrusted": "https://freetsa.org/files/tsa.crt"},
    "digicert.com": {"kind": "system"},
    "sectigo.com": {"kind": "system"},
}

SYSTEM_CA_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",       # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",         # RHEL/Fedora
    "/etc/ssl/cert.pem",                        # Alpine/macOS (brew openssl)
]

OK, FAIL, SKIP = "OK", "FAIL", "SKIP"


class Report:
    def __init__(self):
        self.rows = []

    def add(self, witness, status, detail, independent=False):
        self.rows.append((witness, status, detail, independent))
        mark = {OK: "  OK  ", FAIL: " FAIL ", SKIP: " SKIP "}[status]
        flag = "  [independent]" if independent and status == OK else ""
        print(f"[{mark}] {witness}: {detail}{flag}")

    @property
    def failed(self):
        return any(s == FAIL for _, s, _, _ in self.rows)

    @property
    def independent_ok(self):
        return sum(1 for _, s, _, ind in self.rows if s == OK and ind)


# The Trust Layer edge rejects the default "Python-urllib/x.y" User-Agent with a
# bare 403 — a third party writing their own verifier hits it with no explanation.
# Sending an explicit User-Agent is therefore part of the procedure, not politeness.
USER_AGENT = "arkforge-verify-proof/1.0"


def fetch(url, binary=False, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if binary else data.decode("utf-8")


def openssl(args, stdin=None):
    return subprocess.run(["openssl"] + args, input=stdin,
                          capture_output=True, timeout=30)


def strip_sha256(value):
    return (value or "").replace("sha256:", "")


# --- 1. chain hash -----------------------------------------------------------

# Proofs issued as spec 1.0, 1.1 or 2.0 (and unversioned ones) built the chain hash
# by raw string concatenation. Spec 1.2 and 2.1 use canonical JSON, which removed the
# preimage ambiguity of concatenation. Mirrors trust_layer/proofs.py:159.
LEGACY_SPEC_VERSIONS = {"1.0", "1.1", "2.0", None}
# Spec versions whose chain hash is the Merkle root of per-field commitments.
COMMITMENT_SPEC_VERSIONS = {"3.0", "3.1"}
# Spec versions that commit the identity triple and publish its nonces, so any third
# party opens it from the proof alone. Before 3.1 these three fields were served next
# to the proof but covered by no anchor.
IDENTITY_SPEC_VERSIONS = {"3.1"}
IDENTITY_FIELDS = ("agent_identity", "agent_identity_verified", "did_resolution_status")


def _canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _leaf_hash(data):
    """RFC 6962 leaf hash: sha256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left, right):
    """RFC 6962 interior node: sha256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(leaves):
    """RFC 6962 Merkle Tree Hash over already-hashed leaves.

    The odd node is promoted, never duplicated: duplicating it (the Bitcoin
    shape, CVE-2012-2459) lets two different leaf sets share a root.
    """
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return _node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _commit(field, nonce_hex, value):
    """sha256(field || 0x00 || nonce || canonical_json(value)) — spec 3.0 commitment."""
    preimage = (field.encode("utf-8") + b"\x00" + bytes.fromhex(nonce_hex)
                + _canonical_json(value).encode("utf-8"))
    return hashlib.sha256(preimage).hexdigest()


def check_commitments(proof, rep, disclosure):
    """Spec 3.0: recompute the chain hash as the Merkle root of the commitments.

    Needs no field value, so it works on the public proof — which is the whole
    point of spec 3.0. Disclosed triplets, if any, are checked against the
    commitments they claim to open.
    """
    expected = strip_sha256(proof.get("hashes", {}).get("chain"))
    commitments = proof.get("commitments") or {}
    if not commitments:
        rep.add("chain hash", FAIL,
                "spec 3.0 proof carries no commitments — nothing to recompute the chain hash from")
        return expected
    try:
        leaves = [_leaf_hash(bytes.fromhex(strip_sha256(commitments[f]))) for f in sorted(commitments)]
        computed = _mth(leaves).hex()
    except (ValueError, TypeError, AttributeError) as e:
        rep.add("chain hash", FAIL, f"malformed commitment: {type(e).__name__}: {e}")
        return expected

    if computed != expected:
        rep.add("chain hash", FAIL,
                f"commitment root {computed[:16]}... != published chain {expected[:16]}...")
        return expected
    rep.add("chain hash", OK,
            f"Merkle root of {len(commitments)} field commitments, recomputed from public "
            "data alone (proves nothing on its own)")

    # Spec 3.1 publishes the identity triple's nonces in the proof itself, so this
    # opening needs no out-of-band material. An owner-supplied bundle adds to it.
    disclosed = dict(proof.get("disclosed") or {})
    disclosed.update((disclosure or {}).get("disclosed") or {})
    if not disclosed:
        return expected
    bad = []
    for field, item in sorted(disclosed.items()):
        commitment = strip_sha256(commitments.get(field) or "")
        if not commitment:
            bad.append(f"{field}: no such commitment in the proof")
            continue
        try:
            recomputed = _commit(field, item["nonce"], item["value"])
        except (KeyError, ValueError, TypeError) as e:
            bad.append(f"{field}: unusable triplet ({e})")
            continue
        if recomputed != commitment:
            bad.append(f"{field}: value does not match its commitment")
    if bad:
        rep.add("selective disclosure", FAIL, "; ".join(bad)[:300])
    else:
        rep.add("selective disclosure", OK,
                f"{len(disclosed)} disclosed field(s) match their anchored commitment: "
                + ", ".join(sorted(disclosed)))
    return expected


def check_identity(proof, rep, disclosed, commitments):
    """Spec 3.1: is the agent identity shown the one the anchors cover?

    Deliberately its own witness. The chain-hash line says the published commitments
    reproduce the anchored root; this line says the identity VALUES served alongside
    open those commitments. Before 3.1 the second half did not exist, and an Index
    ranking agents on ``agent_identity_verified`` was ranking on the issuer's word.

    What this establishes is non-repudiation, not third-party verification of the
    binding itself: no public artefact proves the Ed25519 challenge-response ever
    happened. It proves the issuer cannot change its mind after anchoring.
    """
    if proof.get("spec_version") not in IDENTITY_SPEC_VERSIONS:
        claimed = proof.get("agent_identity") or proof.get("agent_identity_verified")
        if not claimed:
            return  # nothing claimed, nothing to say
        rep.add("agent identity", SKIP,
                f"{proof.get('agent_identity') or 'identity'} declared "
                f"(verified={proof.get('agent_identity_verified')!r}) but spec "
                f"{proof.get('spec_version')} predates 3.1: these fields are covered by "
                "no anchor, the issuer can restate them at will — NOT evidence")
        return
    missing = [f for f in IDENTITY_FIELDS if f not in commitments]
    if missing:
        rep.add("agent identity", FAIL,
                "spec 3.1 proof with no commitment for " + ", ".join(missing))
        return
    unopened = [f for f in IDENTITY_FIELDS if f not in disclosed]
    if unopened:
        rep.add("agent identity", FAIL,
                "committed but not opened: " + ", ".join(unopened))
        return
    bad = []
    for field in IDENTITY_FIELDS:
        item = disclosed[field]
        try:
            recomputed = _commit(field, item["nonce"], item["value"])
        except (KeyError, ValueError, TypeError) as e:
            bad.append(f"{field}: unusable triplet ({e})")
            continue
        if recomputed != strip_sha256(commitments[field]):
            bad.append(f"{field}: served value does not match its anchored commitment")
    if bad:
        rep.add("agent identity", FAIL, "; ".join(bad)[:300])
        return
    identity = disclosed["agent_identity"]["value"]
    verified = disclosed["agent_identity_verified"]["value"]
    status = disclosed["did_resolution_status"]["value"]
    if verified is True:
        rep.add("agent identity", OK,
                f"{identity} — verified DID, status {status}; the issuer committed to "
                "this before anchoring and cannot restate it")
    else:
        rep.add("agent identity", OK,
                f"{identity or 'none declared'} — self-declared, NOT a verified DID "
                f"(status {status}); anchored as such")


def check_chain_hash(proof, rep, disclosure=None):
    """Recompute the chain hash from the proof's own fields.

    Deliberately labelled 'self-consistency': it cannot detect a fabricated proof,
    only a corrupted one. It does establish one thing the anchors do not — that the
    anchored chain hash really covers the request and response hashes shown.
    """
    disclosed = dict(proof.get("disclosed") or {})
    disclosed.update((disclosure or {}).get("disclosed") or {})
    check_identity(proof, rep, disclosed, proof.get("commitments") or {})
    if proof.get("spec_version") in COMMITMENT_SPEC_VERSIONS:
        return check_commitments(proof, rep, disclosure)

    expected = strip_sha256(proof.get("hashes", {}).get("chain"))
    parties = proof.get("parties") or {}
    fee = proof.get("certification_fee") or {}

    # Never substitute a neighbouring field for a missing preimage input: that computes
    # a hash over the wrong data and reports a mismatch for the wrong reason.
    missing = []
    if "buyer_fingerprint" not in parties:
        missing.append("parties.buyer_fingerprint")
    if "transaction_id" not in fee:
        missing.append("certification_fee.transaction_id")
    if missing:
        rep.add("chain hash", SKIP,
                "preimage not published (" + ", ".join(missing) + ") — "
                "binding of request/response to the anchored chain hash is not "
                "third-party verifiable")
        return expected

    request_hash = strip_sha256(proof.get("hashes", {}).get("request"))
    response_hash = strip_sha256(proof.get("hashes", {}).get("response"))
    transaction_id = fee.get("transaction_id") or ""
    timestamp = proof.get("timestamp") or ""
    buyer = parties.get("buyer_fingerprint") or ""
    seller = parties.get("seller") or proof.get("seller") or ""
    upstream = proof.get("upstream_timestamp") or ""
    receipt = strip_sha256((proof.get("provider_payment") or {}).get("receipt_content_hash"))

    spec = proof.get("spec_version")
    if spec in LEGACY_SPEC_VERSIONS:
        chain_input = request_hash + response_hash + transaction_id + timestamp + buyer + seller
        if upstream:
            chain_input += upstream
        if receipt:
            chain_input += receipt
        computed = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
        method = "concatenation (legacy spec)"
    else:
        chain_data = {
            "request_hash": request_hash,
            "response_hash": response_hash,
            "transaction_id": transaction_id,
            "timestamp": timestamp,
            "buyer_fingerprint": buyer,
            "seller": seller,
        }
        if upstream:
            chain_data["upstream_timestamp"] = upstream
        if receipt:
            chain_data["receipt_content_hash"] = receipt
        computed = hashlib.sha256(_canonical_json(chain_data).encode("utf-8")).hexdigest()
        method = "canonical JSON (spec 1.2+)"

    if computed == expected:
        rep.add("chain hash", OK, f"self-consistent via {method} (proves nothing on its own)")
    else:
        rep.add("chain hash", FAIL,
                f"recomputed {computed[:16]}... != published {expected[:16]}... [{method}]")
    return expected


# --- 2. Ed25519 --------------------------------------------------------------

_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def check_ed25519(proof, chain_hex, rep, offline):
    sig_str = proof.get("arkforge_signature")
    if not sig_str:
        rep.add("Ed25519 (ArkForge)", SKIP, "proof carries no signature")
        return
    published = None
    if not offline:
        try:
            did = json.loads(fetch(f"{TRUST_LAYER_BASE}/.well-known/did.json"))
            published = did["verificationMethod"][0]["publicKeyJwk"]["x"]
        except Exception as e:
            rep.add("Ed25519 (ArkForge)", FAIL, f"cannot fetch published key: {e}")
            return
    embedded = (proof.get("arkforge_pubkey") or "").replace("ed25519:", "")
    if published and embedded and published != embedded:
        rep.add("Ed25519 (ArkForge)", FAIL,
                "key in proof does not match the key published at did.json")
        return
    pub_b64 = published or embedded
    if not pub_b64:
        rep.add("Ed25519 (ArkForge)", SKIP, "no public key available")
        return
    try:
        raw = _b64url_decode(pub_b64)
        sig = _b64url_decode(sig_str.replace("ed25519:", ""))
    except Exception as e:
        rep.add("Ed25519 (ArkForge)", FAIL, f"malformed key or signature: {e}")
        return

    with tempfile.TemporaryDirectory() as d:
        key = Path(d) / "ed.der"
        key.write_bytes(_ED25519_SPKI_PREFIX + raw)
        sigf = Path(d) / "sig.bin"
        sigf.write_bytes(sig)
        msg = Path(d) / "msg.txt"
        msg.write_bytes(chain_hex.encode("utf-8"))
        r = openssl(["pkeyutl", "-verify", "-pubin", "-inkey", str(key),
                     "-keyform", "DER", "-rawin", "-sigfile", str(sigf),
                     "-in", str(msg)])
    if r.returncode == 0:
        rep.add("Ed25519 (ArkForge)", OK,
                "valid — but the signer is the issuer, not a third party")
    else:
        rep.add("Ed25519 (ArkForge)", FAIL,
                (r.stderr or b"").decode(errors="replace").strip()[:160] or "verification failed")


# --- 3. batch anchor ---------------------------------------------------------

def check_batch_anchor(proof, chain_hex, rep):
    """Walk the inclusion proof from this chain hash up to the anchored batch root.

    Returns the hash the external witnesses actually attest: the batch root when
    the proof is anchored in a batch, the chain hash itself for a proof anchored
    on its own (spec 2.1 and earlier).

    A proof whose batch has not closed yet has no external anchor. That is
    reported as pending, never as a failure: a waiting proof is not a tampered
    one.
    """
    anchor = proof.get("batch_anchor")
    if not anchor:
        return chain_hex
    if anchor.get("status") != "anchored":
        rep.add("batch anchor", SKIP,
                f"batch {anchor.get('batch_id') or '?'} has not closed yet — this proof "
                "carries no external anchor at this point")
        return None
    root = strip_sha256(anchor.get("root"))
    index, size = anchor.get("leaf_index"), anchor.get("tree_size")
    path = anchor.get("audit_path") or []
    if not root or not isinstance(index, int) or not isinstance(size, int) or size < 1:
        rep.add("batch anchor", FAIL, "malformed batch anchor (root, leaf_index or tree_size)")
        return None
    if not 0 <= index < size:
        rep.add("batch anchor", FAIL, f"leaf_index {index} out of range for tree size {size}")
        return None
    expected_len = _expected_path_len(index, size)
    if len(path) != expected_len:
        rep.add("batch anchor", FAIL,
                f"audit path carries {len(path)} nodes, a tree of size {size} needs "
                f"exactly {expected_len} for leaf {index}")
        return None
    try:
        leaf = _leaf_hash(bytes.fromhex(chain_hex))
        computed, consumed = _merkle_root(leaf, index, size, path)
    except (ValueError, IndexError, TypeError, AttributeError) as e:
        # A third party running the published procedure on a malformed file must get
        # a verdict, not a traceback. A traceback is not a refusal.
        rep.add("batch anchor", FAIL, f"malformed audit path: {type(e).__name__}: {e}")
        return None
    if computed.hex() != root:
        rep.add("batch anchor", FAIL,
                f"audit path leads to {computed.hex()[:16]}..., not to the claimed root {root[:16]}...")
        return None
    if consumed != len(path):
        rep.add("batch anchor", FAIL,
                f"audit path carries {len(path)} nodes, {consumed} used by a tree of size {size}")
        return None
    rep.add("batch anchor", OK,
            f"leaf {index} of {size} in batch {anchor.get('batch_id')} — the anchored root "
            "covers this chain hash")
    return root


# --- 4. RFC 3161 -------------------------------------------------------------

def _system_ca_file():
    for c in SYSTEM_CA_CANDIDATES:
        if Path(c).exists():
            return c
    return None


def _no_anchored_hash(proof):
    """Why there is nothing for the external witnesses to check.

    A batch still open and a batch whose inclusion proof does not verify are two
    very different situations; saying 'not yet anchored' for the second hides a
    failure behind a wait.
    """
    if (proof.get("batch_anchor") or {}).get("status") == "anchored":
        return "the batch anchor above did not verify — no anchored hash to check"
    return "nothing anchored yet for this proof"


def check_rfc3161(proof, chain_hex, rep, offline):
    if chain_hex is None:
        rep.add("RFC 3161 timestamp", SKIP, _no_anchored_hash(proof))
        return
    tsa = proof.get("timestamp_authority") or {}
    tsr_b64 = tsa.get("tsr_base64")
    provider = tsa.get("provider") or ""
    if not tsr_b64:
        rep.add("RFC 3161 timestamp", SKIP,
                f"no token in proof (status={tsa.get('status')})")
        return
    source = TSA_CA_SOURCES.get(provider)
    if source is None:
        rep.add("RFC 3161 timestamp", FAIL,
                f"unknown issuer '{provider}' — no CA material mapped for it")
        return

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        # The timestamped artifact is the chain hash DECODED to its 32 raw bytes,
        # not the hex string. Timestamping the hex text yields a verification
        # failure — this is the single detail a third party cannot guess.
        (d / "chain.bin").write_bytes(bytes.fromhex(chain_hex))
        (d / "token.tsr").write_bytes(base64.b64decode(tsr_b64))

        args = ["ts", "-verify", "-data", str(d / "chain.bin"), "-in", str(d / "token.tsr")]
        if source["kind"] == "url":
            if offline:
                rep.add("RFC 3161 timestamp", SKIP,
                        f"{provider} root must be fetched from the TSA (--offline)")
                return
            try:
                (d / "ca.pem").write_bytes(fetch(source["ca"], binary=True))
                (d / "tsa.crt").write_bytes(fetch(source["untrusted"], binary=True))
            except Exception as e:
                rep.add("RFC 3161 timestamp", FAIL, f"cannot fetch {provider} certs: {e}")
                return
            args += ["-CAfile", str(d / "ca.pem"), "-untrusted", str(d / "tsa.crt")]
        else:
            ca = _system_ca_file()
            if ca is None:
                rep.add("RFC 3161 timestamp", FAIL,
                        "no system CA bundle found; set one of " + ", ".join(SYSTEM_CA_CANDIDATES))
                return
            args += ["-CAfile", ca]

        r = openssl(args)

    out = (r.stdout or b"").decode(errors="replace")
    err = (r.stderr or b"").decode(errors="replace")
    if r.returncode == 0 and "Verification: OK" in out:
        what = "batch root" if (proof.get("batch_anchor") or {}).get("status") == "anchored" else "chain hash"
        rep.add("RFC 3161 timestamp", OK,
                f"{provider} signed this {what}", independent=True)
    else:
        rep.add("RFC 3161 timestamp", FAIL,
                (out + " " + err).strip()[:200] or "verification failed")


# --- 5. Rekor ----------------------------------------------------------------

def _expected_path_len(index, size):
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


def _merkle_root(leaf, index, size, path_hashes):
    """RFC 6962 inclusion-proof walk. Returns (root, siblings_consumed).

    A right-edge node is promoted to the next level without consuming a sibling;
    the loop therefore terminates on tree size, not on path exhaustion. The caller
    must check that every sibling was consumed — a leftover one means the proof does
    not match the tree shape that was walked.
    """
    h = leaf
    idx, sz, i = index, size, 0
    while sz > 1:
        if i >= len(path_hashes):
            return h, i   # short path: the caller sees an unreachable root
        if idx % 2 == 1:
            h = hashlib.sha256(b"\x01" + bytes.fromhex(path_hashes[i]) + h).digest()
            i += 1
        elif idx + 1 < sz:
            h = hashlib.sha256(b"\x01" + h + bytes.fromhex(path_hashes[i])).digest()
            i += 1
        idx //= 2
        sz = (sz + 1) // 2
    return h, i


def _verify_ecdsa(pubkey_pem_bytes, signature, message, rep_name, rep):
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "pub.pem").write_bytes(pubkey_pem_bytes)
        (d / "sig.der").write_bytes(signature)
        (d / "msg.bin").write_bytes(message)
        r = openssl(["dgst", "-sha256", "-verify", str(d / "pub.pem"),
                     "-signature", str(d / "sig.der"), str(d / "msg.bin")])
    return r.returncode == 0


def check_rekor(proof, chain_hex, rep, offline):
    if chain_hex is None:
        rep.add("Sigstore Rekor", SKIP, _no_anchored_hash(proof))
        return
    return _check_rekor(proof, chain_hex, rep, offline)


def _check_rekor(proof, chain_hex, rep, offline):
    tl = proof.get("transparency_log") or {}
    uuid = tl.get("uuid")
    if not uuid:
        rep.add("Sigstore Rekor", SKIP,
                f"proof carries no log entry (status={tl.get('status')})")
        return
    if offline:
        rep.add("Sigstore Rekor", SKIP, "requires the public log (--offline)")
        return
    try:
        entry_doc = json.loads(fetch(f"{REKOR_BASE}/api/v1/log/entries/{uuid}"))
        entry = next(iter(entry_doc.values()))
        log_pub = fetch(f"{REKOR_BASE}/api/v1/log/publicKey").encode()
    except Exception as e:
        rep.add("Sigstore Rekor", FAIL, f"cannot fetch log entry: {e}")
        return

    body = base64.b64decode(entry["body"])
    parsed = json.loads(body)

    # Rekor holds several entry kinds. Trust Layer only ever writes hashedrekord;
    # anything else is a different artefact and must be refused, not parsed on faith.
    if parsed.get("kind") != "hashedrekord":
        rep.add("Sigstore Rekor", FAIL,
                f"log entry is of kind '{parsed.get('kind')}', not the hashedrekord "
                "this proof claims — it does not cover this proof's chain hash")
        return
    try:
        spec = parsed["spec"]
        logged_probe = spec["data"]["hash"]["value"]
        spec["signature"]["publicKey"]["content"]
        spec["signature"]["content"]
    except (KeyError, TypeError):
        rep.add("Sigstore Rekor", FAIL, "log entry is malformed for a hashedrekord")
        return
    del logged_probe

    # 4a. The logged artifact must be OUR chain hash. Rekor receives the SHA-256
    # of the chain hash HEX STRING (utf-8), not the chain hash itself. Without
    # this step, "the entry exists" says nothing about whose entry it is.
    expected_leaf_hash = hashlib.sha256(chain_hex.encode("utf-8")).hexdigest()
    logged = spec["data"]["hash"]["value"]
    if logged != expected_leaf_hash:
        rep.add("Sigstore Rekor", FAIL,
                f"log entry covers {logged[:16]}..., not this proof's chain hash")
        return

    # 4b. The entry's own signature, by the submitter's key.
    submitter_pem = base64.b64decode(spec["signature"]["publicKey"]["content"])
    entry_sig = base64.b64decode(spec["signature"]["content"])
    if not _verify_ecdsa(submitter_pem, entry_sig, chain_hex.encode("utf-8"), "entry", rep):
        rep.add("Sigstore Rekor", FAIL, "entry signature does not verify")
        return

    # 4c. Attribution: is the submitting key the one ArkForge publishes?
    attributed = None
    try:
        published = json.loads(fetch(f"{TRUST_LAYER_BASE}/v1/pubkey"))
        pub_rekor = published.get("rekor_pubkey")
        if pub_rekor:
            attributed = _normalise_pem(pub_rekor) == _normalise_pem(submitter_pem.decode())
    except Exception:
        attributed = None

    # 4d. Signed Entry Timestamp: the log itself countersigns the entry.
    set_sig = base64.b64decode(entry["verification"]["signedEntryTimestamp"])
    payload = json.dumps({"body": entry["body"],
                          "integratedTime": entry["integratedTime"],
                          "logID": entry["logID"],
                          "logIndex": entry["logIndex"]},
                         sort_keys=True, separators=(",", ":")).encode()
    if not _verify_ecdsa(log_pub, set_sig, payload, "SET", rep):
        rep.add("Sigstore Rekor", FAIL, "signed entry timestamp does not verify")
        return

    # 4e. Inclusion proof against the signed checkpoint.
    ip = entry["verification"]["inclusionProof"]
    leaf = hashlib.sha256(b"\x00" + body).digest()
    try:
        root, consumed = _merkle_root(leaf, ip["logIndex"], ip["treeSize"], ip["hashes"])
    except IndexError:
        rep.add("Sigstore Rekor", FAIL, "inclusion proof is shorter than the tree requires")
        return
    if root.hex() != ip["rootHash"]:
        rep.add("Sigstore Rekor", FAIL, "inclusion proof does not reach the claimed root")
        return
    if consumed != len(ip["hashes"]):
        rep.add("Sigstore Rekor", FAIL,
                f"inclusion proof carries {len(ip['hashes'])} nodes, {consumed} used")
        return

    cp_body, _, cp_sigblock = ip["checkpoint"].partition("\n\n")
    cp_body += "\n"
    cp_lines = cp_body.strip().split("\n")
    if base64.b64decode(cp_lines[2]).hex() != ip["rootHash"]:
        rep.add("Sigstore Rekor", FAIL, "checkpoint root differs from the inclusion proof root")
        return
    cp_sig_line = next(l for l in cp_sigblock.split("\n") if l.strip())
    cp_raw = base64.b64decode(cp_sig_line.split()[-1])
    key_hint, cp_sig = cp_raw[:4], cp_raw[4:]
    der = openssl(["pkey", "-pubin", "-outform", "DER"], stdin=log_pub).stdout
    if hashlib.sha256(der).digest()[:4] != key_hint:
        rep.add("Sigstore Rekor", FAIL, "checkpoint signed by an unexpected log key")
        return
    if not _verify_ecdsa(log_pub, cp_sig, cp_body.encode(), "checkpoint", rep):
        rep.add("Sigstore Rekor", FAIL, "checkpoint signature does not verify")
        return

    what = "batch root" if (proof.get("batch_anchor") or {}).get("status") == "anchored" else "chain hash"
    detail = (f"{what} in the public log at index {entry['logIndex']}, "
              f"inclusion proof and checkpoint valid")
    if attributed is True:
        detail += "; submitted by ArkForge's published key"
    elif attributed is False:
        rep.add("Sigstore Rekor", FAIL,
                "entry is valid but was submitted by a key ArkForge does not publish")
        return
    else:
        detail += "; submitter key NOT published by ArkForge (attribution unverifiable)"
    rep.add("Sigstore Rekor", OK, detail, independent=True)


def _normalise_pem(pem):
    return "".join(pem.split())


# --- driver ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Verify an ArkForge proof without trusting ArkForge.")
    ap.add_argument("proof_id", nargs="?", help="proof id, e.g. prf_20260303_161853_4d0904")
    ap.add_argument("--file", help="read the proof JSON from a local file instead")
    ap.add_argument("--offline", action="store_true",
                    help="skip every check that needs the network")
    ap.add_argument("--disclose",
                    help="JSON file of disclosed (field, nonce, value) triplets to check "
                         "against the published commitments")
    args = ap.parse_args()

    if args.file:
        proof = json.loads(Path(args.file).read_text())
    elif args.proof_id:
        proof = json.loads(fetch(f"{TRUST_LAYER_BASE}/v1/proof/{args.proof_id}"))
    else:
        ap.error("give a proof id or --file")

    if subprocess.run(["openssl", "version"], capture_output=True).returncode != 0:
        print("openssl is required", file=sys.stderr)
        return 2

    print(f"Proof {proof.get('proof_id')} — spec {proof.get('spec_version')}")
    print()
    disclosure = json.loads(Path(args.disclose).read_text()) if args.disclose else None

    rep = Report()
    chain_hex = check_chain_hash(proof, rep, disclosure)
    check_ed25519(proof, chain_hex, rep, args.offline)
    anchored_hex = check_batch_anchor(proof, chain_hex, rep)
    check_rfc3161(proof, anchored_hex, rep, args.offline)
    check_rekor(proof, anchored_hex, rep, args.offline)

    print()
    if rep.failed:
        print("VERDICT: FAILED — at least one check did not pass.")
        return 1
    if rep.independent_ok == 0:
        print("VERDICT: NOT INDEPENDENTLY VERIFIED — nothing here that ArkForge could not have")
        print("         produced on its own. Self-consistency is not a receipt.")
        return 1
    anchored = (proof.get("batch_anchor") or {}).get("status") == "anchored"
    covers = ("batch root covering this chain hash" if anchored else "chain hash")
    print(f"VERDICT: VERIFIED — {rep.independent_ok} independent witness(es) confirm this")
    print(f"         {covers} existed and was attested outside ArkForge's control.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
