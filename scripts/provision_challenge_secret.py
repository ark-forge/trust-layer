#!/usr/bin/env python3
"""Émet (ou confirme) le secret partagé entre le proxy et le corpus PROVE IT.

Rejouable sans effet de bord : si le secret est déjà au coffre, le script le dit
et sort en succès. Le secret n'est jamais affiché ni journalisé.

    python3 scripts/provision_challenge_secret.py            # émet ou confirme
    python3 scripts/provision_challenge_secret.py --dry-run  # dit ce qu'il ferait
    python3 scripts/provision_challenge_secret.py --rotate   # remplace l'existant

Pourquoi un secret distinct de TRUST_LAYER_INTERNAL_SECRET : le corpus est exposé
aux participants du challenge, alors que le secret interne ouvre le smoke test de
déploiement. Un secret commun ferait de sa rotation un événement pour les deux et
étendrait à un service grand public le secret dont la fuite était la faille v1.7.0.

Pourquoi le coffre et pas settings.env : poser un secret à la main sur l'hôte est
le geste que la procédure de déploiement interdit. `trust_layer/config.py` lit la
section « proveit » du coffre au démarrage, et le déploiement synchronise déjà le
coffre vers le nœud standby (phase 2c). Rien à taper sur une machine.

ROTATION : le corpus et le proxy lisent le même secret. Les remplacer n'est pas
atomique — rotate, puis redéployer le proxy, puis le corpus, dans cet ordre. Entre
les deux, le corpus rend 403 et les participants voient une panne. Le faire hors
saison, ou prévoir côté corpus l'acceptation transitoire de deux secrets.
"""

import argparse
import logging
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

VAULT_SECTION = "proveit"
VAULT_KEY = "challenge_secret"
VAULT_PATH = f"{VAULT_SECTION}.{VAULT_KEY}"
CEO_ROOT = "/opt/claude-ceo"
SECRET_BYTES = 32


def _vault():
    """Coffre du CEO. Dépendance d'hôte, absente des machines de développement."""
    sys.path.insert(0, CEO_ROOT)
    from automation.vault import vault  # noqa: PLC0415
    return vault


def lire_au_coffre() -> str:
    return (_vault().get_section(VAULT_SECTION) or {}).get(VAULT_KEY, "")


def ecrire_au_coffre(secret: str) -> None:
    _vault().set(VAULT_PATH, secret)


def provisionner(lire=lire_au_coffre, ecrire=ecrire_au_coffre,
                 rotate: bool = False, dry_run: bool = False) -> dict:
    """Émet le secret s'il manque. Rend {'created': bool, 'present': bool}.

    Le secret n'est jamais rendu par cette fonction : il ne doit exister qu'au
    coffre. Un appelant qui en aurait besoin le relit lui-même.
    """
    existant = lire()
    if existant and not rotate:
        return {"created": False, "present": True}
    if dry_run:
        return {"created": False, "present": bool(existant), "would_write": True}
    ecrire(secrets.token_urlsafe(SECRET_BYTES))
    return {"created": True, "present": True, "rotated": bool(existant)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="n'écrit rien, dit seulement ce qui serait fait")
    parser.add_argument("--rotate", action="store_true",
                        help="remplace un secret existant (lire la note ROTATION ci-dessus)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        r = provisionner(rotate=args.rotate, dry_run=args.dry_run)
    except ImportError:
        print(f"ÉCHEC : coffre introuvable sous {CEO_ROOT} — à lancer sur l'hôte du CEO.",
              file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - on veut le message, pas la trace
        print(f"ÉCHEC : {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        if r.get("would_write"):
            quoi = "remplacerait" if r["present"] else "écrirait"
            print(f"{quoi} le secret dans {VAULT_PATH}")
        else:
            print(f"secret déjà présent dans {VAULT_PATH} : rien à faire")
        return 0

    if r["created"]:
        quoi = "remplacé" if r.get("rotated") else "créé"
        print(f"secret {quoi} dans {VAULT_PATH} (jamais affiché)")
        print("Suite : redéployer le proxy, puis le corpus. Voir la note ROTATION."
              if r.get("rotated") else
              "Suite : déclarer l'hôte du corpus dans proveit.challenge_hosts, puis déployer.")
    else:
        print(f"secret déjà présent dans {VAULT_PATH}, rien à faire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
