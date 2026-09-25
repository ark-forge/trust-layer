#!/usr/bin/env python3
"""Émet (ou confirme) une clé d'API de PROVE IT.

Rejouable sans effet de bord : si la clé existe déjà, le script le dit et sort
en succès. La clé n'est jamais affichée ni journalisée, elle va au coffre.

    python3 scripts/provision_challenge_key.py                        # clé de l'opérateur
    python3 scripts/provision_challenge_key.py --profil validation    # clé de l'agent de validation
    python3 scripts/provision_challenge_key.py --dry-run              # dit ce qu'il ferait

Profil `challenge` : plan `internal`, qui ne consomme pas de crédits prépayés.
Les preuves du challenge n'empruntent donc pas le chemin de facturation d'un
client (ni débit, ni 402, ni webhook Stripe). C'est assumé, et §6 de la charte
doit le publier.

Profil `validation` : plan `free`, pour passer le challenge comme un participant
(quota compris). Sans email : un email ferait partir un mail par preuve.

Profil `calibration` : plan `internal`, sans email, pour les runs de référence
des profils LLM (prove-it, decisions-goal D5). Six runs dépassent le quota free
de la clé de validation ; une clé à part garde son DID hors de l'historique de
liaison de la clé de l'opérateur.

Profils `reference_soigneux`, `reference_presse`, `reference_sans_verification` : comme `calibration`,
une clé par run de référence de la saison (prove-it D153).

Avant l'ouverture, une clé émise ici n'atteint le corpus qu'une fois autorisée :
`provision_challenge_secret.py --allow-key-ref <ref>`.
"""

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trust_layer.keys import find_key_info_by_ref  # noqa: E402
from trust_layer.provisioning import ProvisioningError, provision_key  # noqa: E402

PROFILS = {
    "challenge": {"ref_id": "proveit_challenge", "plan": "internal",
                  "email": "proveit@arkforge.fr", "vault_path": "proveit.challenge_api_key"},
    "validation": {"ref_id": "proveit_validation", "plan": "free",
                   "email": "", "vault_path": "proveit.validation_api_key"},
    "calibration": {"ref_id": "proveit_calibration", "plan": "internal",
                    "email": "", "vault_path": "proveit.calibration_api_key"},
    # Runs de référence de la saison (prove-it D153) : une clé et un DID chacun, plan internal comme la
    # calibration, lancés une fois après l'ouverture.
    **{f"reference_{p}": {"ref_id": f"proveit_reference_{p}", "plan": "internal",
                          "email": "", "vault_path": f"proveit.reference_{p}_api_key"}
       for p in ("soigneux", "presse", "sans_verification")},
}
CEO_ROOT = "/opt/claude-ceo"


def ecrivain_coffre(vault_path: str):
    """Dépose la clé dans le vault du CEO. Seul endroit où elle atterrit."""
    def ecrire(secret: str) -> None:
        sys.path.insert(0, CEO_ROOT)
        from automation.vault import vault  # noqa: PLC0415 - dépendance d'hôte, pas du paquet

        vault.set(vault_path, secret)
    return ecrire


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profil", choices=sorted(PROFILS), default="challenge",
                        help="quelle clé émettre (défaut : challenge)")
    parser.add_argument("--dry-run", action="store_true",
                        help="n'écrit rien, dit seulement ce qui serait fait")
    args = parser.parse_args()
    p = PROFILS[args.profil]
    ref_id, plan, vault_path = p["ref_id"], p["plan"], p["vault_path"]

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.dry_run:
        existant = find_key_info_by_ref(ref_id)
        if existant is None:
            print(f"créerait une clé « {plan} » pour {ref_id}, déposée dans {vault_path}")
        else:
            etat = "active" if existant.get("active") else "DÉSACTIVÉE"
            print(f"clé déjà présente pour {ref_id} ({etat}) : rien à créer")
        return 0

    try:
        r = provision_key(ref_id, plan=plan, email=p["email"], writer=ecrivain_coffre(vault_path))
    except ProvisioningError as exc:
        print(f"ÉCHEC : {exc}", file=sys.stderr)
        return 1

    if r["created"]:
        print(f"clé « {plan} » créée pour {ref_id}, déposée dans {vault_path}")
    else:
        print(f"clé déjà en place pour {ref_id} (plan {r['plan']}), rien à faire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
