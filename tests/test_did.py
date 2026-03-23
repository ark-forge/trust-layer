"""Tests for GET /.well-known/did.json — W3C DID Document endpoint."""

import base64


def test_did_document_status_200(client):
    resp = client.get("/.well-known/did.json")
    assert resp.status_code == 200


def test_did_document_id(client):
    resp = client.get("/.well-known/did.json")
    data = resp.json()
    assert data["id"] == "did:web:test.arkforge.fr"


def test_did_document_verification_method_type(client):
    resp = client.get("/.well-known/did.json")
    vm = resp.json()["verificationMethod"][0]
    assert vm["type"] == "Ed25519VerificationKey2020"


def test_did_document_public_key_jwk_fields(client):
    resp = client.get("/.well-known/did.json")
    jwk = resp.json()["verificationMethod"][0]["publicKeyJwk"]
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert "x" in jwk


def test_did_document_public_key_x_is_32_bytes(client):
    resp = client.get("/.well-known/did.json")
    x = resp.json()["verificationMethod"][0]["publicKeyJwk"]["x"]
    # Re-add base64url padding
    padding = 4 - len(x) % 4
    if padding != 4:
        x += "=" * padding
    decoded = base64.urlsafe_b64decode(x)
    assert len(decoded) == 32


def test_did_document_auth_and_assertion(client):
    resp = client.get("/.well-known/did.json")
    data = resp.json()
    key_id = data["verificationMethod"][0]["id"]
    assert key_id in data["authentication"]
    assert key_id in data["assertionMethod"]
