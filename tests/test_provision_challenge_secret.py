"""Provisionnement du secret du corpus PROVE IT.

Le coffre vit sur l'hôte du CEO, absent des machines de développement : la
fonction prend donc un lecteur et un écrivain injectables, et ces tests ne
touchent aucun coffre réel.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "provision_challenge_secret",
    Path(__file__).resolve().parents[1] / "scripts" / "provision_challenge_secret.py",
)
prov = importlib.util.module_from_spec(_SPEC)
sys.modules["provision_challenge_secret"] = prov
_SPEC.loader.exec_module(prov)


class Coffre:
    def __init__(self, initial=""):
        self.valeur = initial
        self.ecritures = 0

    def lire(self):
        return self.valeur

    def ecrire(self, secret):
        self.valeur = secret
        self.ecritures += 1


def test_emet_quand_le_coffre_est_vide():
    c = Coffre()
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire)
    assert r["created"] is True
    assert c.ecritures == 1
    assert len(c.valeur) >= 32


def test_rejeu_idempotent():
    """Relancer le script ne doit pas remplacer un secret en service : le proxy
    et le corpus le partagent, une réécriture silencieuse casserait le corpus."""
    c = Coffre("secret-en-service")
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire)
    assert r["created"] is False
    assert c.ecritures == 0
    assert c.valeur == "secret-en-service"


def test_rotate_remplace_explicitement():
    c = Coffre("ancien")
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire, rotate=True)
    assert r["created"] is True and r["rotated"] is True
    assert c.valeur != "ancien" and c.ecritures == 1


def test_dry_run_n_ecrit_jamais():
    for initial in ("", "deja-la"):
        c = Coffre(initial)
        prov.provisionner(lire=c.lire, ecrire=c.ecrire, dry_run=True)
        assert c.ecritures == 0
        assert c.valeur == initial


def test_le_secret_n_est_jamais_rendu():
    """Le secret ne doit exister qu'au coffre. Une fonction qui le rend finit
    dans un log, une sortie de script ou un rapport."""
    c = Coffre()
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire)
    assert c.valeur not in str(r)
    assert not any(isinstance(v, str) and v == c.valeur for v in r.values())


def test_secrets_successifs_differents():
    a, b = Coffre(), Coffre()
    prov.provisionner(lire=a.lire, ecrire=a.ecrire)
    prov.provisionner(lire=b.lire, ecrire=b.ecrire)
    assert a.valeur != b.valeur


class Hotes(Coffre):
    pass


def test_declarer_hotes_ecrit_quand_ca_change():
    h = Hotes("")
    r = prov.declarer_hotes("corpus.arkforge.tech", lire=h.lire, ecrire=h.ecrire)
    assert r["changed"] is True and h.valeur == "corpus.arkforge.tech"


def test_declarer_hotes_idempotent():
    h = Hotes("corpus.arkforge.tech")
    r = prov.declarer_hotes("corpus.arkforge.tech", lire=h.lire, ecrire=h.ecrire)
    assert r["changed"] is False and h.ecritures == 0


def test_declarer_hotes_dry_run_n_ecrit_pas():
    h = Hotes("ancien.example")
    r = prov.declarer_hotes("corpus.arkforge.tech", lire=h.lire, ecrire=h.ecrire, dry_run=True)
    assert h.ecritures == 0 and r["would_write"] == "corpus.arkforge.tech"
