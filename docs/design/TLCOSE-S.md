# TLCOSE-S: COSE_Sign1 signing in tl-signer (R2 design note)

## Goal
Let tl-signer produce a COSE_Sign1 (RFC 9052) over a proof's chain hash, so a proof can
later be exported as a SCITT signed statement (RFC 9943 architecture). This lot is the
signer side only: no API route, no export format, no SCITT registration (later lots).

## Why in the signer
Private keys live only in tl-signer (closed set of operations, bounded validated input,
no key material out). A COSE operation must keep that property: the caller supplies a
chain hash, never a header or free payload, so the signer cannot become a signing oracle.

## Design
- New operation `sign_cose`, input `{"op":"sign_cose","chain_hash":<64 lowercase hex>}`,
  same validation as `sign_chain_hash`. Answer `{"kid":..., "cose":<base64url of COSE_Sign1>}`.
- COSE_Sign1 = CBOR tag 18, array of 4: protected (bstr of map), unprotected (empty map),
  payload (bstr, the 32 raw bytes of the chain hash), signature (64 bytes Ed25519).
- Protected header, built by the signer only: 1 (alg) = -8 (EdDSA, RFC 9053; widely
  supported), 4 (kid) = bstr of "{did}#{kid}", 3 (content type) = "application/vnd.arkforge.chain-hash",
  15 (CWT claims) = {1 (iss): did, 2 (sub): "sha256:<chain_hash>"}.
- Signature input = Sig_structure ["Signature1", protected, h'', payload], RFC 9052 s4.4.
- Same Ed25519 key as proofs (published in key history); no new key.
- CBOR is encoded by a ~30-line deterministic encoder inside tl_signer.py (ints, bstr, tstr,
  map, array, tag only). The signer keeps depending on the standard library and `cryptography`.
- Client: `SocketSigner.sign_cose(chain_hash)` and `LocalSigner.sign_cose(chain_hash)`
  returning the same bytes layout. Nothing calls them yet.

## Tests (red first)
1. Output parses back (independent minimal CBOR decoder in the test) as tag 18 with 4 elements.
2. The signature verifies with the published Ed25519 public key over the Sig_structure.
3. Protected header carries alg -8, kid, iss = did, sub = "sha256:" + chain_hash.
4. Invalid chain_hash (length, uppercase, non-hex, missing) refused; unknown extra fields ignored.
5. LocalSigner and SocketSigner produce a verifiable statement for the same input.
6. Cross-check against a third-party COSE implementation (pycose, dev requirement only) if installable.

## Out of scope
Export endpoint, SCITT registration, receipts, any change to existing operations or proofs.

## Risk
R2 (protocol, signing). Existing operations untouched; new operation is additive. Rollback = remove the op.
