"""Émission de la clé du challenge PROVE IT.

Le geste manuel est exclu : l'émission doit être rejouable, donc idempotente, et
ne jamais laisser la clé ailleurs que dans le coffre.
"""

import pytest

from trust_layer.keys import create_api_key, deactivate_key_by_ref, get_key_plan
from trust_layer.provisioning import ProvisioningError, provision_key

REF = "proveit_challenge"


class Coffre:
    """Coffre de test : retient ce qu'on lui écrit, et sait échouer sur commande."""

    def __init__(self, en_panne=False):
        self.contenu = {}
        self.en_panne = en_panne

    def __call__(self, secret: str) -> None:
        if self.en_panne:
            raise RuntimeError("coffre injoignable")
        self.contenu["key"] = secret


def test_premiere_emission_cree_la_cle_et_la_depose_au_coffre():
    coffre = Coffre()
    r = provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=coffre)

    assert r["created"] is True
    assert r["plan"] == "internal"
    assert coffre.contenu["key"].startswith("mcp_int_")
    assert get_key_plan(coffre.contenu["key"]) == "internal"


def test_le_rejeu_ne_cree_pas_une_seconde_cle():
    """Rejouable : c'est ce qui distingue un chemin d'exploitation d'un geste."""
    premier = Coffre()
    provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=premier)

    second = Coffre()
    r = provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=second)

    assert r["created"] is False
    # Rien n'est réécrit : un rejeu ne doit pas écraser le coffre avec autre chose.
    assert second.contenu == {}


def test_cle_free_sans_email_pour_l_agent_de_validation():
    """L'agent de validation passe comme un participant (plan free), mais sans
    email : un email ferait partir un mail par preuve."""
    coffre = Coffre()
    r = provision_key("proveit_validation", plan="free", email="", writer=coffre)

    assert r["created"] is True and r["plan"] == "free"
    assert get_key_plan(coffre.contenu["key"]) == "free"
    from trust_layer.keys import find_key_info_by_ref
    assert find_key_info_by_ref("proveit_validation")["email"] == ""


def test_la_cle_n_est_jamais_dans_le_compte_rendu():
    """Le compte rendu est journalisé ; la clé n'a rien à y faire."""
    coffre = Coffre()
    r = provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=coffre)

    assert coffre.contenu["key"] not in repr(r)
    assert all("mcp_int_" not in str(v) for v in r.values())


def test_une_cle_existante_desactivee_est_une_erreur_pas_un_succes():
    """Sinon on croit disposer d'une clé utilisable alors qu'elle renvoie 401."""
    provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=Coffre())
    deactivate_key_by_ref(REF)

    with pytest.raises(ProvisioningError, match="désactivée"):
        provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=Coffre())


def test_une_cle_existante_du_mauvais_plan_est_une_erreur():
    """Réutiliser une clé `pro` pour le challenge donnerait des quotas faux en silence."""
    create_api_key("cus_x", REF, "proveit@smoke.invalid", plan="pro")

    with pytest.raises(ProvisioningError, match="plan"):
        provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=Coffre())


def test_un_coffre_en_panne_ne_laisse_pas_une_cle_valide_orpheline():
    """Une clé qui existe sans être au coffre est un secret actif que personne ne connaît."""
    coffre = Coffre(en_panne=True)

    with pytest.raises(ProvisioningError, match="coffre"):
        provision_key(REF, plan="internal", email="proveit@smoke.invalid", writer=coffre)

    from trust_layer.keys import find_key_info_by_ref
    info = find_key_info_by_ref(REF)
    assert info is None or info["active"] is False
