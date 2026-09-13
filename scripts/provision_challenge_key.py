#!/usr/bin/env python3
"""Émet (ou confirme) la clé d'API du challenge PROVE IT.

Rejouable sans effet de bord : si la clé existe déjà, le script le dit et sort
en succès. La clé n'est jamais affichée ni journalisée, elle va au coffre.

    python3 scripts/provision_challenge_key.py            # émet ou confirme
    python3 scripts/provision_challenge_key.py --dry-run  # dit ce qu'il ferait

Le plan `internal` ne consomme pas de crédits prépayés : les preuves du challenge
n'empruntent donc pas le chemin de facturation d'un client (ni débit, ni 402, ni
webhook Stripe). C'est assumé, et §6 de la charte doit le publier.
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trust_layer.keys import find_key_info_by_ref  # noqa: E402
from trust_layer.provisioning import ProvisioningError, provision_key  # noqa: E402

REF_ID = "proveit_challenge"
PLAN = "internal"
EMAIL = "proveit@arkforge.fr"
VAULT_PATH = "proveit.challenge_api_key"
CEO_ROOT = "/opt/claude-ceo"


def ecrire_au_coffre(secret: str) -> None:
    """Dépose la clé dans le vault du CEO. Seul endroit où elle atterrit."""
    sys.path.insert(0, CEO_ROOT)
    from automation.vault import vault  # noqa: PLC0415 - dépendance d'hôte, pas du paquet

    vault.set(VAULT_PATH, secret)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="n'écrit rien, dit seulement ce qui serait fait")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.dry_run:
        existant = find_key_info_by_ref(REF_ID)
        if existant is None:
            print(f"créerait une clé « {PLAN} » pour {REF_ID}, déposée dans {VAULT_PATH}")
        else:
            etat = "active" if existant.get("active") else "DÉSACTIVÉE"
            print(f"clé déjà présente pour {REF_ID} ({etat}) : rien à créer")
        return 0

    try:
        r = provision_key(REF_ID, plan=PLAN, email=EMAIL, writer=ecrire_au_coffre)
    except ProvisioningError as exc:
        print(f"ÉCHEC : {exc}", file=sys.stderr)
        return 1

    if r["created"]:
        print(f"clé « {PLAN} » créée pour {REF_ID}, déposée dans {VAULT_PATH}")
    else:
        print(f"clé déjà en place pour {REF_ID} (plan {r['plan']}), rien à faire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
