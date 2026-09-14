"""Provisionnement du secret du corpus PROVE IT.

Le coffre vit sur l'hôte du CEO, absent des machines de développement : la
fonction prend donc un lecteur et un écrivain injectables, et ces tests ne
touchent aucun coffre réel.
"""

import copy
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

    def relire(self):
        return self.valeur


def test_emet_quand_le_coffre_est_vide():
    c = Coffre()
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire, relire=c.relire)
    assert r["created"] is True
    assert c.ecritures == 1
    assert len(c.valeur) >= 32


def test_rejeu_idempotent():
    """Relancer le script ne doit pas remplacer un secret en service : le proxy
    et le corpus le partagent, une réécriture silencieuse casserait le corpus."""
    c = Coffre("secret-en-service")
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire, relire=c.relire)
    assert r["created"] is False
    assert c.ecritures == 0
    assert c.valeur == "secret-en-service"


def test_rotate_remplace_explicitement():
    c = Coffre("ancien")
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire, relire=c.relire, rotate=True)
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
    r = prov.provisionner(lire=c.lire, ecrire=c.ecrire, relire=c.relire)
    assert c.valeur not in str(r)
    assert not any(isinstance(v, str) and v == c.valeur for v in r.values())


def test_secrets_successifs_differents():
    a, b = Coffre(), Coffre()
    prov.provisionner(lire=a.lire, ecrire=a.ecrire, relire=a.relire)
    prov.provisionner(lire=b.lire, ecrire=b.ecrire, relire=b.relire)
    assert a.valeur != b.valeur


class Hotes(Coffre):
    pass


def test_declarer_hotes_ecrit_quand_ca_change():
    h = Hotes("")
    r = prov.declarer_hotes("corpus.arkforge.tech", lire=h.lire, ecrire=h.ecrire, relire=h.relire)
    assert r["changed"] is True and h.valeur == "corpus.arkforge.tech"


def test_declarer_hotes_idempotent():
    h = Hotes("corpus.arkforge.tech")
    r = prov.declarer_hotes("corpus.arkforge.tech", lire=h.lire, ecrire=h.ecrire)
    assert r["changed"] is False and h.ecritures == 0


def test_declarer_hotes_dry_run_n_ecrit_pas():
    h = Hotes("ancien.example")
    r = prov.declarer_hotes("corpus.arkforge.tech", lire=h.lire, ecrire=h.ecrire, dry_run=True)
    assert h.ecritures == 0 and r["would_write"] == "corpus.arkforge.tech"


# --- Clés autorisées avant l'ouverture ----------------------------------------

CLE = "mcp_int_" + "c" * 48


def _trouver(infos):
    return lambda ref: infos.get(ref)


def _empreinte(cle):
    import hashlib
    return hashlib.sha256(cle.encode("utf-8")).hexdigest()


def test_autoriser_cle_ajoute_l_empreinte_jamais_la_cle():
    c = Coffre("")
    r = prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, relire=c.relire,
                           trouver=_trouver({"proveit_challenge": {"active": True, "_key": CLE}}))
    assert r["changed"] is True
    assert c.valeur == _empreinte(CLE)
    assert CLE not in c.valeur and CLE not in str(r)


def test_autoriser_cle_garde_les_empreintes_existantes_et_rejoue_sans_ecrire():
    autre = "d" * 64
    c = Coffre(autre)
    trouver = _trouver({"proveit_challenge": {"active": True, "_key": CLE}})
    prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, relire=c.relire, trouver=trouver)
    assert set(c.valeur.split(",")) == {autre, _empreinte(CLE)}

    r = prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, trouver=trouver)
    assert r["changed"] is False and c.ecritures == 1


def test_autoriser_cle_dry_run_n_ecrit_pas():
    c = Coffre("")
    r = prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, dry_run=True,
                           trouver=_trouver({"proveit_challenge": {"active": True, "_key": CLE}}))
    assert c.ecritures == 0 and r["would_write"] is True


@pytest.mark.parametrize("infos", [{}, {"proveit_challenge": {"active": False, "_key": CLE}}])
def test_autoriser_cle_inconnue_ou_desactivee_est_une_erreur(infos):
    """Autoriser une ref sans clé active ferait croire le corpus accessible."""
    c = Coffre("")
    with pytest.raises(prov.ErreurCoffre):
        prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, trouver=_trouver(infos))
    assert c.ecritures == 0


class CoffrePartage(Coffre):
    """Un autre écrivain réécrit le coffre juste après nous, depuis sa copie d'avant.

    C'est la course réelle : `automation.vault` réécrit tout le fichier depuis sa
    copie en mémoire, sans verrou. Notre écriture est perdue sans erreur.
    """

    def __init__(self, initial=""):
        super().__init__(initial)
        self.sur_disque = initial

    def ecrire(self, valeur):
        super().ecrire(valeur)
        # l'autre processus avait lu avant nous et réécrit sa copie : notre valeur disparaît

    def relire(self):
        return self.sur_disque


def test_autoriser_cle_ecrasee_par_un_autre_ecrivain_est_une_erreur():
    """Sans relecture, le script annonce « empreinte ajoutée » et le proxy ne la verra jamais."""
    c = CoffrePartage("")
    with pytest.raises(prov.ErreurCoffre):
        prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, relire=c.relire,
                           trouver=_trouver({"proveit_challenge": {"active": True, "_key": CLE}}))


def test_autoriser_cle_relue_intacte_passe():
    c = CoffrePartage("")
    c.relire = lambda: c.valeur
    r = prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, relire=c.relire,
                           trouver=_trouver({"proveit_challenge": {"active": True, "_key": CLE}}))
    assert r["changed"] is True


def test_fermer_la_saison_ecrasee_par_un_autre_ecrivain_est_une_erreur():
    """Le cas qui compte : un --close perdu laisse la saison ouverte à toutes les clés."""
    c = CoffrePartage("true")
    with pytest.raises(prov.ErreurCoffre):
        prov.declarer_saison(False, lire=c.lire, ecrire=c.ecrire, relire=c.relire)


def test_rotation_ecrasee_par_un_autre_ecrivain_est_une_erreur():
    """Rotation après fuite : annoncer « remplacé » alors que l'ancien secret reste au coffre
    laisse le secret compromis en service."""
    c = CoffrePartage("ancien-secret-fuite")
    with pytest.raises(prov.ErreurCoffre):
        prov.provisionner(lire=c.lire, ecrire=c.ecrire, relire=c.relire, rotate=True)


def test_declarer_hotes_ecrase_par_un_autre_ecrivain_est_une_erreur():
    c = CoffrePartage("")
    with pytest.raises(prov.ErreurCoffre):
        prov.declarer_hotes("corpus.arkforge.tech", lire=c.lire, ecrire=c.ecrire, relire=c.relire)


def test_autoriser_cle_relue_avec_une_empreinte_perdue_est_une_erreur():
    """L'autre écrivain a gardé notre empreinte mais perdu une clé déjà autorisée."""
    autre = "d" * 64
    c = CoffrePartage(autre)
    c.relire = lambda: _empreinte(CLE)
    with pytest.raises(prov.ErreurCoffre):
        prov.autoriser_cle("proveit_challenge", lire=c.lire, ecrire=c.ecrire, relire=c.relire,
                           trouver=_trouver({"proveit_challenge": {"active": True, "_key": CLE}}))


def test_main_hotes_ecrases_sort_en_echec_propre(monkeypatch, capsys):
    """Une écriture perdue sur les hôtes rend ÉCHEC et rc 1, pas une trace Python."""
    monkeypatch.setattr(prov, "provisionner", lambda **kw: {"created": False, "present": True})

    def perdu(*a, **kw):
        raise prov.ErreurCoffre("écrasé")
    monkeypatch.setattr(prov, "declarer_hotes", perdu)
    monkeypatch.setattr(sys, "argv", ["provision_challenge_secret.py", "--host", "corpus.arkforge.tech"])
    assert prov.main() == 1
    assert "ÉCHEC" in capsys.readouterr().err


class FauxVault:
    """Même comportement que `automation.vault` : copie en mémoire chargée une fois, `reload` la vide."""

    def __init__(self, disque):
        self.disque = disque
        self.memoire = None

    def reload(self):
        self.memoire = None

    def get_section(self, section):
        if self.memoire is None:
            self.memoire = copy.deepcopy(self.disque)
        return dict(self.memoire.get(section, {}))


@pytest.mark.parametrize("relire,champ", [
    ("relire_secret", "challenge_secret"), ("relire_hotes", "challenge_hosts"),
    ("relire_cles", "challenge_keys"), ("relire_saison", "challenge_open"),
])
def test_relecture_par_defaut_lit_le_disque_pas_la_copie_en_memoire(monkeypatch, relire, champ):
    """Câblage réel : sans `reload`, la relecture retrouverait toujours notre propre écriture."""
    v = FauxVault({"proveit": {champ: "valeur-en-memoire"}})
    monkeypatch.setattr(prov, "_vault", lambda: v)
    v.get_section("proveit")
    v.disque["proveit"][champ] = "valeur-d-un-autre-ecrivain"
    assert getattr(prov, relire)() == "valeur-d-un-autre-ecrivain"


def test_declarer_saison_ecrit_true_ou_false_et_rejoue():
    c = Coffre("")
    assert prov.declarer_saison(True, lire=c.lire, ecrire=c.ecrire, relire=c.relire)["changed"] is True
    assert c.valeur == "true"
    assert prov.declarer_saison(True, lire=c.lire, ecrire=c.ecrire, relire=c.relire)["changed"] is False
    prov.declarer_saison(False, lire=c.lire, ecrire=c.ecrire, relire=c.relire)
    assert c.valeur == "false" and c.ecritures == 2


def test_declarer_saison_dry_run_n_ecrit_pas():
    c = Coffre("false")
    r = prov.declarer_saison(True, lire=c.lire, ecrire=c.ecrire, dry_run=True)
    assert c.ecritures == 0 and r["would_write"] == "true"
