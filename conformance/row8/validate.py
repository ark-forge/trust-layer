#!/usr/bin/env python3
# validate.py - ArkForge Row 8 substrate verifier (urn:arkforge:verdict)
#
# Verifies the tier_upgrade_proof reference fixture and its negative test
# vectors. Standard library only: no pip, no cryptography package. Ed25519
# verification is a pure-Python port of the RFC 8032 reference implementation.
# Deterministic: the script never reads the system clock. Every vector carries
# its own verification_time, used for the temporal checks.
#
# Usage:
#   python3 validate.py [vector.json ...]
#   python3 validate.py --did-json /path/to/did.json [vector.json ...]
#
# With no path arguments it loads vectors/*.json relative to this file.
#
# Reproducibility note for reviewers:
#   Run with python3 alone. No network access is performed during the test run.
#   The signing public key is embedded below and MUST equal publicKeyJwk.x of
#   verificationMethod ...#key-1 at
#   https://trust.arkforge.tech/.well-known/did.json. A third party can confirm
#   the embedded value out of band with: curl that URL and compare the x field.

import sys
import os
import json
import glob
import base64
import hashlib

# ---------------------------------------------------------------------------
# Embedded signing key.
#
# This is publicKeyJwk.x (base64url, no padding) for the verificationMethod
# whose id ends in #key-1 at https://trust.arkforge.tech/.well-known/did.json.
# It is embedded so the test run is deterministic and offline. Resolving the
# live did.json during the test run is intentionally NOT done here; pass
# --did-json to override with a locally fetched copy if you want to confirm
# the embedded value matches the published document.
EMBEDDED_PUBLIC_KEY_B64URL = "ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY"
EMBEDDED_KID = "did:web:trust.arkforge.tech#key-1"


# ===========================================================================
# Ed25519 verification, pure Python.
#
# Adapted from the reference implementation in RFC 8032 (Edwards-Curve Digital
# Signature Algorithm), Appendix A / Section 6. The reference code is published
# by the IETF for implementation purposes. SHA-512 is provided by hashlib so
# the only arithmetic here is the curve math. Only the verify path is needed
# for this validator; signing is deliberately absent because no private key is
# available and negative vectors are altered copies of the valid signature,
# never freshly signed material.
# ===========================================================================

# Curve constant: 2^255 - 19
_P = 2 ** 255 - 19
# Group order
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _sha512_int(b):
    return int.from_bytes(_sha512(b), "little")


def _inv(x):
    # Modular inverse via Fermat's little theorem.
    return pow(x, _P - 2, _P)


def _x_recover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


# Base point B.
_BY = (4 * _inv(5)) % _P
_BX = _x_recover(_BY)
_B = [_BX % _P, _BY % _P]


def _edwards(p, q):
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return [x3 % _P, y3 % _P]


def _scalarmult(p, e):
    if e == 0:
        return [0, 1]
    q = _scalarmult(p, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, p)
    return q


def _encode_int(y):
    bits = [(y >> i) & 1 for i in range(256)]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32)
    )


def _decode_int(s):
    return int.from_bytes(s, "little")


def _decode_point(s):
    y = _decode_int(s) & ((1 << 255) - 1)
    x = _x_recover(y)
    if x & 1 != (_decode_int(s) >> 255) & 1:
        x = _P - x
    p = [x, y]
    if not _is_on_curve(p):
        raise ValueError("decoded point is not on the curve")
    return p


def _is_on_curve(p):
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def ed25519_verify(public_key, message, signature):
    """Return True if signature is a valid Ed25519 signature of message under
    public_key. public_key is 32 bytes, signature is 64 bytes. Never raises on
    a malformed-but-wrong signature; returns False instead, except for inputs
    of the wrong length which are programmer errors."""
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")
    if len(public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    try:
        a = _decode_point(public_key)
    except ValueError:
        return False
    r_bytes = signature[:32]
    s_int = _decode_int(signature[32:])
    if s_int >= _L:
        # Non-canonical S. Reject.
        return False
    try:
        r = _decode_point(r_bytes)
    except ValueError:
        return False
    h = _sha512_int(r_bytes + public_key + message) % _L
    # Check [s]B == R + [h]A
    lhs = _scalarmult(_B, s_int)
    rhs = _edwards(r, _scalarmult(a, h))
    return lhs[0] == rhs[0] and lhs[1] == rhs[1]


# ===========================================================================
# JCS canonicalization (subset).
#
# RFC 8785 JSON Canonicalization Scheme, restricted to the value types this
# substrate uses: objects, arrays, strings, integers, booleans, null. Floats
# are rejected explicitly: RFC 8785 number canonicalization (ECMAScript
# Number-to-String) is not implemented here, and the fixture contains no
# floats, so any float is treated as out of scope rather than silently mis
# canonicalized.
# ===========================================================================

class JcsError(Exception):
    pass


def _jcs_check_no_floats(obj, path="$"):
    if isinstance(obj, float):
        raise JcsError(
            "float value at %s is not supported by this JCS subset; "
            "this substrate contains only objects, arrays, strings, "
            "integers, booleans and null" % path
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise JcsError("non-string object key at %s" % path)
            _jcs_check_no_floats(v, "%s.%s" % (path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _jcs_check_no_floats(v, "%s[%d]" % (path, i))


def jcs_canonicalize(obj):
    """Return the canonical UTF-8 bytes for obj under the supported subset.
    Raises JcsError if a float appears anywhere in the structure."""
    _jcs_check_no_floats(obj)
    # json.dumps with sort_keys gives RFC 8785 object key ordering for the
    # ASCII key set used here, compact separators, and bool is rendered as
    # true/false, null as null. ints render without a fractional part. floats
    # are already excluded above.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ===========================================================================
# Helpers
# ===========================================================================

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_public_key(did_json_path):
    """Return (public_key_bytes, kid). If did_json_path is None use the
    embedded key. Otherwise parse the supplied did.json and extract
    publicKeyJwk.x from the verificationMethod whose id ends in #key-1."""
    if did_json_path is None:
        return b64url_decode(EMBEDDED_PUBLIC_KEY_B64URL), EMBEDDED_KID
    with open(did_json_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    methods = doc.get("verificationMethod", [])
    chosen = None
    for m in methods:
        mid = m.get("id", "")
        if mid.endswith("#key-1"):
            chosen = m
            break
    if chosen is None and methods:
        chosen = methods[0]
    if chosen is None:
        raise ValueError("no verificationMethod in %s" % did_json_path)
    jwk = chosen.get("publicKeyJwk", {})
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("verificationMethod is not an Ed25519 OKP key")
    x = jwk["x"]
    return b64url_decode(x), chosen.get("id", "")


# ===========================================================================
# Checks. Each returns (passed: bool, detail: str). They run in this order.
# The first failing check determines failing_check for the vector.
# ===========================================================================

CHECK_ORDER = [
    "jcs_hash",
    "jws_signature",
    "kid_binding",
    "scope_binding",
    "requester_binding",
    "expiry",
]


def _get(d, *keys):
    cur = d
    for k in keys:
        cur = cur[k]
    return cur


def check_jcs_hash(fixture):
    env = _get(fixture, "output", "ctef_envelope")
    claimed = _get(fixture, "output", "envelope_sha256")
    canon = jcs_canonicalize(env)
    got = hashlib.sha256(canon).hexdigest()
    if got != claimed:
        return False, "JCS sha256 %s != envelope_sha256 %s" % (got, claimed)
    return True, "JCS sha256 matches (%d bytes)" % len(canon)


def check_jws_signature(fixture, public_key):
    jws = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "approval_evidence", "verdict_jws",
    )
    parts = jws.split(".")
    if len(parts) != 3:
        return False, "verdict_jws is not a three part compact JWS"
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(b64url_decode(h_b64))
    except Exception as e:
        return False, "cannot decode JWS header: %s" % e
    if header.get("alg") != "EdDSA":
        return False, "JWS alg is %r, expected EdDSA" % header.get("alg")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    signature = b64url_decode(s_b64)
    if len(signature) != 64:
        return False, "JWS signature is %d bytes, expected 64" % len(signature)
    if ed25519_verify(public_key, signing_input, signature):
        return True, "EdDSA signature valid"
    return False, "EdDSA signature does not verify against the signing key"


def check_kid_binding(fixture):
    jws = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "approval_evidence", "verdict_jws",
    )
    h_b64 = jws.split(".")[0]
    header = json.loads(b64url_decode(h_b64))
    kid = header.get("kid", "")
    approver = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "approval_evidence", "approver_did",
    )
    if not approver:
        return False, "approver_did is empty"
    if not kid.startswith(approver):
        return False, (
            "header.kid %r does not start with approver_did %r"
            % (kid, approver)
        )
    return True, "kid %r bound to approver_did %r" % (kid, approver)


def check_scope_binding(fixture):
    jws = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "approval_evidence", "verdict_jws",
    )
    p_b64 = jws.split(".")[1]
    payload = json.loads(b64url_decode(p_b64))
    payload_scope = payload.get("scope_boundary")
    fixture_scope = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "validity", "scope_boundary",
    )
    if payload_scope != fixture_scope:
        return False, (
            "payload.scope_boundary %r != validity.scope_boundary %r"
            % (payload_scope, fixture_scope)
        )
    return True, "scope_boundary %r consistent" % payload_scope


def check_requester_binding(fixture):
    jws = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "approval_evidence", "verdict_jws",
    )
    p_b64 = jws.split(".")[1]
    payload = json.loads(b64url_decode(p_b64))
    payload_req = payload.get("requester_did")
    proof_req = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "requester_did",
    )
    if payload_req != proof_req:
        return False, (
            "payload.requester_did %r != tier_upgrade_proof.requester_did %r"
            % (payload_req, proof_req)
        )
    return True, "requester_did %r consistent" % payload_req


def check_expiry(fixture, verification_time):
    valid_until = _get(
        fixture, "output", "ctef_envelope", "tier_upgrade_proof",
        "validity", "valid_until",
    )
    # ISO 8601 UTC Z timestamps. Lexicographic comparison is correct for this
    # fixed format (same length, same offset). No clock is read; the vector's
    # verification_time is the only time source.
    if verification_time > valid_until:
        return False, (
            "verification_time %s is after valid_until %s"
            % (verification_time, valid_until)
        )
    return True, (
        "verification_time %s within valid_until %s"
        % (verification_time, valid_until)
    )


def run_checks(fixture, verification_time, public_key):
    """Run the checks in order. Return (valid, failing_check, details).
    valid is True only if every check passes. failing_check is the name of the
    first check that failed, or None."""
    details = {}
    failing_check = None

    runners = {
        "jcs_hash": lambda: check_jcs_hash(fixture),
        "jws_signature": lambda: check_jws_signature(fixture, public_key),
        "kid_binding": lambda: check_kid_binding(fixture),
        "scope_binding": lambda: check_scope_binding(fixture),
        "requester_binding": lambda: check_requester_binding(fixture),
        "expiry": lambda: check_expiry(fixture, verification_time),
    }

    for name in CHECK_ORDER:
        try:
            passed, detail = runners[name]()
        except JcsError as e:
            passed, detail = False, "JCS error: %s" % e
        except Exception as e:
            passed, detail = False, "%s raised %s: %s" % (
                name, type(e).__name__, e
            )
        details[name] = (passed, detail)
        if not passed and failing_check is None:
            failing_check = name

    valid = failing_check is None
    return valid, failing_check, details


# ===========================================================================
# Vector driver
# ===========================================================================

REQUIRED_VECTOR_KEYS = [
    "vector_id", "failure_mode", "description",
    "verification_time", "fixture", "expected",
]

# The pinned suite. When running against the default vectors/ directory the
# loaded vector_ids must match this set exactly, so a silently dropped (or
# smuggled-in) vector fails the run instead of shrinking it.
EXPECTED_VECTOR_IDS = [
    "neg-expired-verdict-001",
    "neg-kid-mismatch-001",
    "neg-requester-binding-001",
    "neg-rescoped-replay-001",
    "neg-tampered-signature-001",
    "valid-001",
]


def load_vectors(paths):
    vectors = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            v = json.load(fh)
        for k in REQUIRED_VECTOR_KEYS:
            if k not in v:
                raise ValueError(
                    "%s missing required key %r" % (path, k)
                )
        exp = v["expected"]
        if "valid" not in exp or "failing_check" not in exp:
            raise ValueError(
                "%s expected must contain valid and failing_check" % path
            )
        v["_path"] = path
        vectors.append(v)
    return vectors


def main(argv):
    args = argv[1:]
    did_json_path = None
    vector_paths = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--did-json":
            if i + 1 >= len(args):
                sys.stderr.write("--did-json requires a path\n")
                return 2
            did_json_path = args[i + 1]
            i += 2
            continue
        vector_paths.append(a)
        i += 1

    full_suite = not vector_paths
    if not vector_paths:
        here = os.path.dirname(os.path.abspath(__file__))
        default_glob = os.path.join(here, "vectors", "*.json")
        vector_paths = sorted(glob.glob(default_glob))
        if not vector_paths:
            sys.stderr.write(
                "no vectors given and no files match %s\n" % default_glob
            )
            return 2

    try:
        public_key, key_id = load_public_key(did_json_path)
    except Exception as e:
        sys.stderr.write("cannot load public key: %s\n" % e)
        return 2

    key_source = "embedded" if did_json_path is None else did_json_path
    print("signing key source: %s (kid=%s)" % (key_source, key_id))
    print("public key (b64url): %s" % base64.urlsafe_b64encode(
        public_key).decode("ascii").rstrip("="))
    print()

    try:
        vectors = load_vectors(vector_paths)
    except Exception as e:
        sys.stderr.write("vector load error: %s\n" % e)
        return 2

    seen_ids = [v["vector_id"] for v in vectors]
    if len(seen_ids) != len(set(seen_ids)):
        dupes = sorted(set(i for i in seen_ids if seen_ids.count(i) > 1))
        sys.stderr.write("duplicate vector_id(s): %s\n" % ", ".join(dupes))
        return 2
    if full_suite:
        missing = sorted(set(EXPECTED_VECTOR_IDS) - set(seen_ids))
        extra = sorted(set(seen_ids) - set(EXPECTED_VECTOR_IDS))
        if missing or extra:
            if missing:
                sys.stderr.write(
                    "pinned suite incomplete, missing: %s\n"
                    % ", ".join(missing))
            if extra:
                sys.stderr.write(
                    "unexpected vector_id(s) not in pinned suite: %s\n"
                    % ", ".join(extra))
            return 2
        print("pinned suite: %d/%d expected vectors present"
              % (len(seen_ids), len(EXPECTED_VECTOR_IDS)))
        print()

    rows = []
    all_ok = True
    for v in vectors:
        valid, failing_check, details = run_checks(
            v["fixture"], v["verification_time"], public_key
        )
        exp = v["expected"]
        exp_valid = exp["valid"]
        exp_fail = exp["failing_check"]
        matched = (valid == exp_valid) and (failing_check == exp_fail)
        if not matched:
            all_ok = False
        rows.append({
            "vector_id": v["vector_id"],
            "failure_mode": v["failure_mode"],
            "got_valid": valid,
            "got_fail": failing_check,
            "exp_valid": exp_valid,
            "exp_fail": exp_fail,
            "matched": matched,
            "details": details,
        })

    _print_table(rows)
    print()
    if all_ok:
        print("RESULT: all %d vector(s) matched expectations" % len(rows))
        return 0
    nbad = sum(1 for r in rows if not r["matched"])
    print("RESULT: %d of %d vector(s) did NOT match expectations"
          % (nbad, len(rows)))
    return 1


def _fmt_fail(f):
    return "-" if f is None else f


def _print_table(rows):
    header = ["vector_id", "got_valid", "got_failing", "exp_valid",
              "exp_failing", "match"]
    table = [header]
    for r in rows:
        table.append([
            r["vector_id"],
            "true" if r["got_valid"] else "false",
            _fmt_fail(r["got_fail"]),
            "true" if r["exp_valid"] else "false",
            _fmt_fail(r["exp_fail"]),
            "ok" if r["matched"] else "MISMATCH",
        ])
    widths = [max(len(row[c]) for row in table) for c in range(len(header))]
    for ri, row in enumerate(table):
        line = "  ".join(row[c].ljust(widths[c]) for c in range(len(header)))
        print(line)
        if ri == 0:
            print("  ".join("-" * widths[c] for c in range(len(header))))
    # Per vector check detail for any mismatch, to aid hostile review.
    for r in rows:
        if not r["matched"]:
            print()
            print("MISMATCH detail for %s:" % r["vector_id"])
            for name in CHECK_ORDER:
                passed, detail = r["details"][name]
                print("    %-18s %s  %s"
                      % (name, "pass" if passed else "FAIL", detail))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
