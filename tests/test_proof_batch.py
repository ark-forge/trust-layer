"""POST /v1/proofs — lecture groupée des vues publiques, réservée aux preuves PROVE IT.

Rejouer un score lit une trentaine de preuves ; une par une, trois scores par heure épuisent le seuil
anti-abus d'une IP. Le lot compte pour une lecture. Il ne sert que les preuves dont le seller est un hôte
PROVE IT : une preuve client n'est pas lisible en lot, et le lot ne dit pas si elle existe.
"""

import json
from unittest.mock import patch

import pytest

from trust_layer.proofs import store_proof, load_proof

CORPUS = "prf_20260915_100000_aaaaaa"
GEL = "prf_20260915_100000_bbbbbb"
CLIENT = "prf_20260915_100000_cccccc"
ABSENTE = "prf_20260915_100000_dddddd"


@pytest.fixture
def preuves():
    for pid, seller in ((CORPUS, "corpus.arkforge.tech"), (GEL, "proveit.arkforge.tech"),
                        (CLIENT, "api.client.example")):
        store_proof(pid, {"proof_id": pid, "spec_version": "3.0", "views_count": 0,
                          "hashes": {"chain": "sha256:" + "0" * 64},
                          "batch_anchor": {"status": "anchored"},
                          "parties": {"seller": seller}})


class _FakeRedis:
    def __init__(self, store=None):
        self.store = dict(store or {})

    def get(self, key):
        return self.store.get(key)

    def incr(self, key):
        self.store[key] = str(int(self.store.get(key) or 0) + 1)
        return int(self.store[key])

    def expire(self, key, ttl):
        pass


def _lot(client, ids):
    return client.post("/v1/proofs", json={"proof_ids": ids})


def test_vues_proveit_servies_client_et_absente_a_null(client, preuves):
    r = _lot(client, [CORPUS, GEL, CLIENT, ABSENTE])
    assert r.status_code == 200
    vues = r.json()["proofs"]
    assert set(vues) == {CORPUS, GEL, CLIENT, ABSENTE}
    assert vues[CORPUS]["seller"] == "corpus.arkforge.tech" and vues[CORPUS]["proof_id"] == CORPUS
    assert vues[GEL]["seller"] == "proveit.arkforge.tech"
    assert "integrity_verified" in vues[CORPUS]
    assert vues[CLIENT] is None and vues[ABSENTE] is None


def test_vue_du_lot_identique_a_la_vue_unitaire_hors_compteur(client, preuves):
    lot = _lot(client, [CORPUS]).json()["proofs"][CORPUS]
    unitaire = client.get(f"/v1/proof/{CORPUS}").json()
    lot.pop("views_count"), unitaire.pop("views_count")
    assert lot == unitaire


def test_lot_n_incremente_pas_views_count(client, preuves):
    _lot(client, [CORPUS, GEL])
    assert load_proof(CORPUS)["views_count"] == 0 and load_proof(GEL)["views_count"] == 0


@pytest.mark.parametrize("corps", [
    {"proof_ids": ["../../etc/passwd"]},
    {"proof_ids": [CORPUS, 42]},
    {"proof_ids": []},
    {"proof_ids": "prf_20260915_100000_aaaaaa"},
    {},
    {"proof_ids": [f"prf_20260915_100000_{i:06x}" for i in range(51)]},
])
def test_lot_mal_forme_refuse_en_entier(client, preuves, corps):
    assert client.post("/v1/proofs", json=corps).status_code == 400


def test_json_invalide_400(client):
    r = client.post("/v1/proofs", content=b"{", headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_cinquante_identifiants_acceptes(client, preuves):
    ids = [f"prf_20260915_100000_{i:06x}" for i in range(50)]
    assert _lot(client, ids).status_code == 200


def test_doublons_servis_une_fois(client, preuves):
    assert list(_lot(client, [CORPUS, CORPUS]).json()["proofs"]) == [CORPUS]


def test_lot_compte_une_lecture_et_journalise_chaque_preuve(client, preuves, tmp_path):
    redis = _FakeRedis()
    with patch("trust_layer.app.get_redis", return_value=redis):
        assert _lot(client, [CORPUS, GEL, CLIENT, ABSENTE]).status_code == 200
    assert redis.store["proof_abuse:testclient"] == "1"
    lignes = [json.loads(l) for l in (tmp_path / "data" / "proof_access_log.jsonl").read_text().splitlines()]
    assert [l["proof_id"] for l in lignes] == [CORPUS, GEL, CLIENT, ABSENTE]


def test_ip_au_dela_du_seuil_bloquee_sur_le_lot(client, preuves):
    redis = _FakeRedis({"proof_abuse:testclient": "101"})
    with patch("trust_layer.app.get_redis", return_value=redis):
        r = _lot(client, [CORPUS])
    assert r.status_code == 429 and redis.store["proof_abuse:testclient"] == "101"


def test_lot_et_vue_unitaire_partagent_le_compteur(client, preuves):
    redis = _FakeRedis({"proof_abuse:testclient": "100"})
    with patch("trust_layer.app.get_redis", return_value=redis):
        assert _lot(client, [CORPUS]).status_code == 200
        assert client.get(f"/v1/proof/{CORPUS}").status_code == 429
