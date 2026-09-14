"""GET /v1/keys/identity : le porteur d'une clé lit le DID lié à sa clé et son historique.

Consommateur : le service de saison PROVE IT (un DID par clé, DID liés à une même clé = un participant).
La route ne rend que l'identité : ni email, ni plan, ni référence de paiement.
"""

from trust_layer.did_resolver import bind_did_to_key

CHAMPS = {"verified_did", "verified_did_method", "verified_did_bound_at", "verified_did_history"}


def test_sans_cle_401(client):
    assert client.get("/v1/keys/identity").status_code == 401


def test_cle_invalide_401(client):
    assert client.get("/v1/keys/identity", headers={"X-Api-Key": "mcp_test_inexistante"}).status_code == 401


def test_cle_sans_did_lie(client, test_api_key):
    resp = client.get("/v1/keys/identity", headers={"X-Api-Key": test_api_key})

    assert resp.status_code == 200
    assert resp.json() == {"verified_did": None, "verified_did_method": None,
                           "verified_did_bound_at": None, "verified_did_history": []}


def test_did_lie_et_historique_seulement(client, test_api_key):
    bind_did_to_key(test_api_key, "did:key:z6MkPremier", "challenge_response")
    bind_did_to_key(test_api_key, "did:key:z6MkSecond", "challenge_response")

    resp = client.get("/v1/keys/identity", headers={"Authorization": f"Bearer {test_api_key}"})

    assert resp.status_code == 200
    data = resp.json()
    assert set(data) == CHAMPS
    assert (data["verified_did"], data["verified_did_method"]) == ("did:key:z6MkSecond", "challenge_response")
    assert [h["did"] for h in data["verified_did_history"]] == ["did:key:z6MkPremier"]
    assert set(data["verified_did_history"][0]) == {"did", "bound_at", "method", "unbound_at"}
    assert "test@example.com" not in resp.text
