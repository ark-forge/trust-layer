# Row 8 conformance: `urn:arkforge:verdict`

Conformance fixtures and a stdlib-only validator for the Row 8 substrate
(`urn:arkforge:verdict`) of the CTEF v0.3.3 federation matrix.

## Discrimination tuple

Row 8 is discriminated by:

```
(authority, cryptographic, did:web:trust.arkforge.tech)
```

- `authority`: the claim asserts a policy decision (a tier-upgrade grant), not
  an observation or a measurement.
- `cryptographic`: the decision is carried by an EdDSA/Ed25519 compact JWS
  (`header.payload.signature`), verifiable against a published key.
- `did:web:trust.arkforge.tech`: the gateway DID that signs the verdict.

Normative rules:

> A gateway-verdict row MUST set `source_provider_did` to the gateway DID. No
> passthrough of the evaluated emitter's DID.

> The `verdict_jws` MUST be signed by the gateway DID (the same DID that
> appears as `source_provider_did` / `approver_did`). A signature that verifies
> under any other key is not a gateway verdict.

> The envelope MUST carry a reference to the emitter row's fingerprint so the
> non-repudiation chain is explicit: a verifier can trace the evaluated agent
> back to its matrix row without re-resolving the DID document. See
> *What this does not cover* for the current fixture's scope.

`source_provider_did` is the matrix-level name of the tuple's third component;
this fixture predates that field name and realizes it as `issuer_did` plus the
JWS header `kid`, both `did:web:trust.arkforge.tech`. The emitter being
evaluated is `did:web:requester.example`; it appears in the verdict only as
`requester_did`, the bound subject of the decision. The signing authority is
the gateway, and that is what a verifier trusts. The `kid_binding` check below
enforces the no-passthrough rule on the fixture's actual fields.

## Provenance

The reference fixture was published on 2026-05-19 in A2A discussion #1734, at:

```
https://github.com/a2aproject/A2A/discussions/1734#discussioncomment-16981095
```

The unmodified fixture is embedded in `vectors/valid-001.json` under the
`fixture` key, so the positive vector is the published fixture and needs no
external file to verify.

The signing key is resolved by DID:

```
did:web:trust.arkforge.tech
  -> https://trust.arkforge.tech/.well-known/did.json
  -> verificationMethod id "...#key-1"
  -> publicKeyJwk.x = "ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY"
```

`publicKeyJwk.kty` is `OKP`, `crv` is `Ed25519`. The 32-byte public key is the
base64url decoding of `publicKeyJwk.x`. The validator embeds this value so the
test run is deterministic and offline; each fixture also pins it in
`verification.public_key_b64url`. The value is the one served live at the URL
above, and any third party can re-resolve it and pass it back in with
`--did-json` to confirm the embedded key matches the published document.

## Test vectors

There is one positive vector (the unmodified fixture) and five negative
vectors. Each negative vector is a single controlled alteration of the valid
fixture. No negative vector is re-signed: the gateway private key is not
available, so every negative case is engineered to fail exactly one check.

The suite is pinned: `validate.py` embeds the expected vector_id list and a
default run fails if any vector is missing, duplicated, or unexpected, so a
dropped negative case cannot silently shrink the run.

Each vector carries its own `verification_time` so temporal checks are
deterministic and do not read the system clock.

| file                               | failure_mode        | check that fails    |
|------------------------------------|---------------------|---------------------|
| `valid-001.json`                   | none (accepts)      | none (accepts)      |
| `neg-tampered-signature-001.json`  | tampered_signature  | `jws_signature`     |
| `neg-kid-mismatch-001.json`        | kid_mismatch        | `kid_binding`       |
| `neg-rescoped-replay-001.json`     | rescoped_replay     | `scope_binding`     |
| `neg-requester-binding-001.json`   | requester_rebinding | `requester_binding` |
| `neg-expired-verdict-001.json`     | expired_verdict     | `expiry`            |

How each negative isolates a single check:

- `neg-tampered-signature-001`: bytes of the 64-byte signature segment are
  flipped and re-encoded base64url. The envelope hash is recomputed so
  `jcs_hash` passes, and the signature no longer verifies, so `jws_signature`
  is the first and only failure.
- `neg-kid-mismatch-001`: the unsigned envelope field
  `approval_evidence.approver_did` is rewritten to `did:web:attacker.example`.
  The signed JWS is the genuine reference signature, untouched, so
  `jws_signature` still passes. `kid_binding` then fails because the signed
  header `kid` (`did:web:trust.arkforge.tech#key-1`) no longer starts with the
  asserted `approver_did`. Mutating the JWS header `kid` itself is not used,
  because the header is part of the signing input and that would break
  `jws_signature` first. Tampering the unsigned `approver_did` is the only way
  to exercise `kid_binding` while keeping the signature valid.
- `neg-rescoped-replay-001`: the envelope `validity.scope_boundary` is
  rewritten to a hijacked session. The signed payload keeps the original scope,
  so the signature still verifies and the envelope hash is recomputed; only
  `scope_binding` trips on the payload-versus-envelope mismatch.
- `neg-requester-binding-001`: the envelope
  `tier_upgrade_proof.requester_did` is rewritten to
  `did:web:attacker.example` while the signed payload keeps the original
  requester. Same isolation pattern as `neg-rescoped-replay-001` on the
  requester axis: the envelope hash is recomputed, the signature still
  verifies, and only `requester_binding` trips.
- `neg-expired-verdict-001`: the fixture is unmodified; the vector's
  `verification_time` is set to `2026-05-19T21:00:00Z`, after `valid_until`
  `2026-05-19T20:45:00Z`. All crypto and binding checks pass and only `expiry`
  fails.

The validator reports the first failing check in evaluation order, so vector
design and check order together fix which check is credited with the failure.

## How to run

```
python3 validate.py
```

To confirm the embedded key against the live DID document, fetch it and pass
it back in:

```
curl -s https://trust.arkforge.tech/.well-known/did.json -o did.json
python3 validate.py --did-json did.json
```

No dependencies. Python 3 standard library only: `json`, `base64`, `hashlib`.
Ed25519 verification is a pure-Python implementation of RFC 8032 section 6,
using `hashlib.sha512` for the internal hash. There is no `pip install` and no
`cryptography` import.

Expected output. The validator prints the signing key source, a per-vector
table comparing the computed result against each vector's `expected` block, and
a summary line. Vectors are listed in filename order:

```
signing key source: embedded (kid=did:web:trust.arkforge.tech#key-1)
public key (b64url): ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY

pinned suite: 6/6 expected vectors present

vector_id                   got_valid  got_failing        exp_valid  exp_failing        match
--------------------------  ---------  -----------------  ---------  -----------------  -----
neg-expired-verdict-001     false      expiry             false      expiry             ok
neg-kid-mismatch-001        false      kid_binding        false      kid_binding        ok
neg-requester-binding-001   false      requester_binding  false      requester_binding  ok
neg-rescoped-replay-001     false      scope_binding      false      scope_binding      ok
neg-tampered-signature-001  false      jws_signature      false      jws_signature      ok
valid-001                   true       -                  true       -                  ok

RESULT: all 6 vector(s) matched expectations
```

The process exits 0 when every vector matches its expected outcome and exits
non-zero otherwise, printing a per-check breakdown for each mismatch.

## Check order and semantics

The validator runs the following checks in this fixed order and stops at the
first failure. The order is cheapest-and-most-structural first, so a tampered
envelope is rejected before any signature math runs.

1. `jcs_hash`
   Re-serialize `output.ctef_envelope` with JCS for this subset and SHA-256 it.
   The serialization is:

   ```python
   json.dumps(obj, sort_keys=True, separators=(',', ':'),
              ensure_ascii=False).encode('utf-8')
   ```

   The digest MUST equal `output.envelope_sha256`. For the unmodified
   reference fixture that digest is
   `47f24a4bfb8fd3ef65e9ce6b0900cffc1018c9d18fab777b1022aedff649aa14` and the
   canonical form is 1340 bytes, recorded in `output.envelope_jcs_bytes`. The
   check compares the recomputed digest against `output.envelope_sha256`; it
   does not separately assert the byte count, which is informational. This
   binds the on-the-wire envelope to a fixed canonical form before anything
   else is trusted.

2. `jws_signature`
   Split `approval_evidence.verdict_jws` into `header.payload.signature`.
   Build the signing input as `base64url(header) + "." + base64url(payload)`,
   exactly the bytes between the dots, with no re-encoding. Verify the 64-byte
   Ed25519 signature over that input against the gateway public key. That key
   is embedded in the validator (and equals each fixture's
   `verification.public_key_b64url`); `--did-json` overrides it with a locally
   fetched `did.json`. Failure means the verdict bytes are not the bytes the
   gateway signed.

3. `kid_binding`
   The JWS header `kid` MUST start with the envelope
   `approval_evidence.approver_did`. For this fixture the header `kid` is
   `did:web:trust.arkforge.tech#key-1` and `approver_did` is
   `did:web:trust.arkforge.tech`, so the key id is bound to the asserting
   authority. This prevents a signature that verifies under some other key, or
   a verdict whose declared approver does not match the signing key id, from
   being accepted as a verdict from this gateway.

4. `scope_binding`
   The JWS payload `scope_boundary` MUST equal the envelope
   `tier_upgrade_proof.validity.scope_boundary`
   (`session:ctef-tier-upgrade-fixture-v1`). The signed scope and the
   envelope's declared scope must be the same session.

5. `requester_binding`
   The JWS payload `requester_did` MUST equal the envelope
   `tier_upgrade_proof.requester_did` (`did:web:requester.example`). This binds
   the proof to one principal and closes the session-intercept replay window
   that `scope_boundary` alone does not close.

6. `expiry`
   The vector's `verification_time` MUST NOT be after
   `tier_upgrade_proof.validity.valid_until` (`2026-05-19T20:45:00Z`); a
   `verification_time` strictly greater than `valid_until` fails. Comparison is
   on the RFC 3339 UTC strings, which are lexicographically ordered for this
   fixed `Z`-suffixed format. No system clock is read.

A verdict is accepted only if all six checks pass.

## What this does not cover

- No emitter row fingerprint. The third normative rule above requires the
  envelope to carry a reference to the evaluated emitter's matrix row
  fingerprint. The reference fixture predates this requirement and the field is
  absent from `valid-001.json`. Adding it to the signed JWS payload would
  require the gateway private key; adding it only to the unsigned envelope
  would change the JCS hash, invalidating the pinned SHA-256. A future fixture
  produced with access to the gateway private key should include an
  `emitter_row_fingerprint` field in the signed payload and document the
  expected value here.

- No signed `certified: false` vector and no `certified` check. Producing a
  verdict whose payload says `certified: false` and that still verifies would
  require the gateway private key, which is not available here. The reference
  payload asserts `certified: true`, but the validator does not inspect the
  `certified` field; it verifies the signature, the bindings, and expiry. A
  validly signed refusal is therefore out of scope for this conformance set,
  both as a vector and as a check.

- No full RFC 8785 JCS. The hashing in `jcs_hash` is the JCS rule restricted to
  this fixture's value types: objects, arrays, strings, integers, booleans, and
  null. It does not implement RFC 8785 number canonicalization. The fixture
  contains no floating-point numbers. An input carrying a float is rejected
  rather than canonicalized, so the validator never silently produces a wrong
  digest for a value type it does not handle.

- Short verdict TTL by design. The reference verdict is valid for one hour
  (`issued_at` 2026-05-19T19:45:00Z, `valid_until` 2026-05-19T20:45:00Z) and
  `use_count_max` is 1. The `expiry` check uses each vector's pinned
  `verification_time` rather than wall-clock time, so these fixtures remain
  reproducible after the real verdict has long expired. A live integration must
  use real time and will reject this fixture as expired, which is the intended
  behavior of a short-TTL single-use grant.
