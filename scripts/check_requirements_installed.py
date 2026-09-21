#!/usr/bin/env python3
"""Compare les épingles d'un requirements.txt aux paquets installés dans le venv qui l'exécute.

Lancé par deploy_trust_layer_prod.sh avec le python du venv de service, après `pip install -r` :
une montée de dépendance n'est en prod que si ce contrôle passe. Sort 1 et liste les écarts sinon.

Usage : <venv>/bin/python scripts/check_requirements_installed.py requirements.txt
"""

import re
import sys
from importlib import metadata
from pathlib import Path


def normaliser(nom: str) -> str:
    return re.sub(r"[-_.]+", "-", nom).lower()


def epingles(chemin: Path) -> dict[str, str]:
    """{nom normalisé: version} ; suit les `-r`. Toute ligne sans `==` est refusée."""
    res: dict[str, str] = {}
    for brute in Path(chemin).read_text().splitlines():
        ligne = brute.split("#", 1)[0].strip()
        if not ligne:
            continue
        if ligne.startswith("-r "):
            res.update(epingles(Path(chemin).parent / ligne[3:].strip()))
            continue
        nom, sep, version = ligne.partition("==")
        if not sep or not version.strip():
            raise ValueError(f"ligne non épinglée : {ligne}")
        res[normaliser(nom.strip())] = version.strip()
    return res


def _version_installee(nom: str) -> str | None:
    try:
        return metadata.version(nom)
    except metadata.PackageNotFoundError:
        return None


def ecarts(chemin: Path, installee=_version_installee) -> list[tuple[str, str, str | None]]:
    """[(nom, voulu, installé ou None)] pour chaque épingle non satisfaite."""
    return [
        (nom, voulu, eue)
        for nom, voulu in epingles(chemin).items()
        if (eue := installee(nom)) != voulu
    ]


if __name__ == "__main__":
    liste = ecarts(Path(sys.argv[1]))
    for nom, voulu, eue in liste:
        print(f"{nom}: voulu {voulu}, installé {eue or 'absent'}")
    sys.exit(1 if liste else 0)
