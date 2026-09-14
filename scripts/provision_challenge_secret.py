#!/usr/bin/env python3
"""Émet (ou confirme) le secret partagé entre le proxy et le corpus PROVE IT.

Rejouable sans effet de bord : si le secret est déjà au coffre, le script le dit
et sort en succès. Le secret n'est jamais affiché ni journalisé.

    python3 scripts/provision_challenge_secret.py            # émet ou confirme
    python3 scripts/provision_challenge_secret.py --dry-run  # dit ce qu'il ferait
    python3 scripts/provision_challenge_secret.py --rotate   # remplace l'existant
    python3 scripts/provision_challenge_secret.py --allow-key-ref proveit_challenge
    python3 scripts/provision_challenge_secret.py --open     # ouvre la saison (--close)

Avant l'ouverture, le proxy ne transmet le secret qu'aux clés listées dans
`proveit.challenge_keys`, par empreinte sha256 et jamais par valeur. Tout le
monde obtient une clé par /v1/keys/free-signup : sans cette liste, le corpus
privé serait lisible par n'importe qui dès que son DNS existe. Seul
`challenge_open = true` ouvre la saison ; un coffre illisible la laisse fermée.
Le proxy lit le coffre au démarrage : redéployer après chaque changement.

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
import hashlib
import logging
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

VAULT_SECTION = "proveit"
VAULT_KEY = "challenge_secret"
VAULT_PATH = f"{VAULT_SECTION}.{VAULT_KEY}"
HOSTS_KEY = "challenge_hosts"
HOSTS_PATH = f"{VAULT_SECTION}.{HOSTS_KEY}"
KEYS_KEY = "challenge_keys"
KEYS_PATH = f"{VAULT_SECTION}.{KEYS_KEY}"
OPEN_KEY = "challenge_open"
OPEN_PATH = f"{VAULT_SECTION}.{OPEN_KEY}"
CEO_ROOT = "/opt/claude-ceo"
SECRET_BYTES = 32


class ErreurCoffre(RuntimeError):
    """Écriture refusée : elle ferait croire à un état qui n'est pas le vrai."""


def _vault():
    """Coffre du CEO. Dépendance d'hôte, absente des machines de développement."""
    sys.path.insert(0, CEO_ROOT)
    from automation.vault import vault  # noqa: PLC0415
    return vault


def lire_au_coffre() -> str:
    return (_vault().get_section(VAULT_SECTION) or {}).get(VAULT_KEY, "")


def ecrire_au_coffre(secret: str) -> None:
    _vault().set(VAULT_PATH, secret)


def lire_hotes() -> str:
    return (_vault().get_section(VAULT_SECTION) or {}).get(HOSTS_KEY, "")


def ecrire_hotes(hotes: str) -> None:
    _vault().set(HOSTS_PATH, hotes)


def _lire_champ(cle: str) -> str:
    return (_vault().get_section(VAULT_SECTION) or {}).get(cle, "")


def lire_cles() -> str:
    return _lire_champ(KEYS_KEY)


def ecrire_cles(valeur: str) -> None:
    _vault().set(KEYS_PATH, valeur)


def lire_saison() -> str:
    return _lire_champ(OPEN_KEY)


def ecrire_saison(valeur: str) -> None:
    _vault().set(OPEN_PATH, valeur)


def _trouver_cle(ref: str):
    from trust_layer.keys import find_key_info_by_ref  # noqa: PLC0415 - lit api_keys.json de l'hôte
    return find_key_info_by_ref(ref)


def autoriser_cle(ref: str, lire=lire_cles, ecrire=ecrire_cles, trouver=_trouver_cle,
                  dry_run: bool = False) -> dict:
    """Ajoute l'empreinte de la clé active de `ref` à la liste d'avant ouverture.

    Seule l'empreinte va au coffre et au compte rendu, jamais la clé.
    """
    info = trouver(ref)
    if not info or not info.get("active"):
        raise ErreurCoffre(f"aucune clé active pour « {ref} » : rien à autoriser")
    empreinte = hashlib.sha256(info["_key"].encode("utf-8")).hexdigest()
    actuelles = [e.strip() for e in lire().split(",") if e.strip()]
    if empreinte in actuelles:
        return {"changed": False, "ref": ref, "count": len(actuelles)}
    if dry_run:
        return {"changed": False, "ref": ref, "count": len(actuelles), "would_write": True}
    ecrire(",".join(actuelles + [empreinte]))
    return {"changed": True, "ref": ref, "count": len(actuelles) + 1}


def declarer_saison(ouverte: bool, lire=lire_saison, ecrire=ecrire_saison,
                    dry_run: bool = False) -> dict:
    """Écrit l'état de saison. Toujours explicite : « true » ou « false »."""
    voulu = "true" if ouverte else "false"
    actuel = lire()
    if actuel == voulu:
        return {"changed": False, "value": actuel}
    if dry_run:
        return {"changed": False, "value": actuel, "would_write": voulu}
    ecrire(voulu)
    return {"changed": True, "value": voulu, "previous": actuel}


def declarer_hotes(hotes: str, lire=lire_hotes, ecrire=ecrire_hotes,
                   dry_run: bool = False) -> dict:
    """Déclare l'allowlist des hôtes du corpus. Sans elle le secret est inerte.

    Laisser ce geste à un humain sur l'hôte, c'est la main sur settings.env que la
    procédure de déploiement interdit — et un secret posé sans allowlist journalise
    une erreur à chaque démarrage.
    """
    actuel = lire()
    if actuel == hotes:
        return {"changed": False, "value": actuel}
    if dry_run:
        return {"changed": False, "value": actuel, "would_write": hotes}
    ecrire(hotes)
    return {"changed": True, "value": hotes, "previous": actuel}


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


def _rapporter_hotes(args) -> None:
    """Applique et rapporte l'allowlist. Appelé sur les deux chemins, dry-run compris."""
    if not args.host:
        if not lire_hotes():
            print(f"ATTENTION : {HOSTS_PATH} est vide, le secret restera inerte. "
                  f"Relancer avec --host <domaine>.")
        return
    h = declarer_hotes(",".join(args.host), dry_run=args.dry_run)
    if h.get("would_write"):
        print(f"écrirait {HOSTS_PATH} = {h['would_write']} (actuel : {h['value'] or 'vide'})")
    elif h["changed"]:
        print(f"{HOSTS_PATH} = {h['value']} (avant : {h.get('previous') or 'vide'})")
    else:
        print(f"{HOSTS_PATH} déjà à {h['value']}, rien à faire")


def _rapporter_acces(args) -> None:
    """Clés autorisées et état de saison. Appelé sur les deux chemins, dry-run compris."""
    for ref in args.allow_key_ref:
        r = autoriser_cle(ref, dry_run=args.dry_run)
        if r.get("would_write"):
            print(f"ajouterait l'empreinte de la clé « {ref} » à {KEYS_PATH} ({r['count']} déjà)")
        elif r["changed"]:
            print(f"empreinte de la clé « {ref} » ajoutée à {KEYS_PATH} ({r['count']} au total)")
        else:
            print(f"clé « {ref} » déjà autorisée, rien à faire")
    if args.saison is not None:
        s = declarer_saison(args.saison, dry_run=args.dry_run)
        if s.get("would_write"):
            print(f"écrirait {OPEN_PATH} = {s['would_write']} (actuel : {s['value'] or 'vide'})")
        elif s["changed"]:
            print(f"{OPEN_PATH} = {s['value']} (avant : {s.get('previous') or 'vide'})")
        else:
            print(f"{OPEN_PATH} déjà à {s['value']}, rien à faire")
    if args.allow_key_ref or args.saison is not None:
        print("Suite : redéployer le proxy (il lit le coffre au démarrage).")


def _rapporter_acces_ou_echouer(args) -> int:
    try:
        _rapporter_acces(args)
    except ErreurCoffre as exc:
        print(f"ÉCHEC : {exc}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="n'écrit rien, dit seulement ce qui serait fait")
    parser.add_argument("--rotate", action="store_true",
                        help="remplace un secret existant (lire la note ROTATION ci-dessus)")
    parser.add_argument("--host", action="append", default=[], metavar="HOTE",
                        help="hôte du corpus à autoriser (répétable) ; sans lui le secret est inerte")
    parser.add_argument("--allow-key-ref", action="append", default=[], metavar="REF",
                        help="autorise avant ouverture la clé active de cette ref (répétable)")
    saison = parser.add_mutually_exclusive_group()
    saison.add_argument("--open", dest="saison", action="store_const", const=True,
                        help="ouvre la saison : toute clé reçoit le secret")
    saison.add_argument("--close", dest="saison", action="store_const", const=False,
                        help="ferme la saison : seules les clés autorisées le reçoivent")
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
        # surtout pas de return ici : un dry-run qui tait la moitié de ce qu'il
        # ferait est pire qu'absent, il fait valider une action non annoncée.
        _rapporter_hotes(args)
        return _rapporter_acces_ou_echouer(args)

    if r["created"]:
        quoi = "remplacé" if r.get("rotated") else "créé"
        print(f"secret {quoi} dans {VAULT_PATH} (jamais affiché)")
        if r.get("rotated"):
            print("Suite : redéployer le proxy, puis le corpus. Voir la note ROTATION.")
    else:
        print(f"secret déjà présent dans {VAULT_PATH}, rien à faire")

    _rapporter_hotes(args)
    return _rapporter_acces_ou_echouer(args)


if __name__ == "__main__":
    sys.exit(main())
