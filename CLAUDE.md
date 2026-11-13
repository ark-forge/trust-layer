# Trust Layer : consignes pour les agents qui codent ici
API FastAPI de certification : preuves signées (Ed25519), horodatage RFC 3161, ancrage Sigstore Rekor, paiements Stripe.
Le signeur des clés privées est un processus séparé (`signer/`, socket Unix) ; la prod tourne sur deux nœuds.

## Stack et langue
- Python 3.11 (Dockerfile, `ci.yml`, `release.yml`) ; paquets via pip, dépendances en locks à hashes
  (`requirements.in` → `requirements.txt`, `requirements-dev.in` → `requirements-dev.txt`, compilés avec uv pour
  Python 3.14, constat à ne pas trancher). Tests : pytest, pytest-asyncio, fakeredis (extra `test` de `setup.py`).
- Langue du code : anglais (identifiants, commentaires, docstrings, noms de tests), pour tout code neuf, y compris dans un fichier existant en français ; pas de renommage de masse. Docs publiques (README, `docs/`, CHANGELOG) et textes affichés aux utilisateurs : anglais. Commits : `git log` montre des titres en français (forme « sujet : effet (version) ») ; seuls les `Merge pull request` de GitHub sont en anglais.

## Commandes (exactes, à lancer sur les fichiers touchés)
- Tests ciblés : `pytest tests/test_<module>.py -v` (CI : `pip install -e ".[test]"`, puis `python3 -m trust_layer.crypto` pour générer la clé de test, puis `pytest tests/ -v`)
- Lint : `ruff check <fichiers>` (config `ruff.toml`, base commune). La CI ne lint que les `.py` modifiés ; ne jamais lancer sur tout le dépôt pour corriger.
- Typage, format, check : sans objet (ni mypy ni formateur configurés). Contrôle du lock : `uv pip compile requirements.in --python-platform linux --python-version 3.14 --generate-hashes` (idem `requirements-dev`), comparé par la CI.
- Suite entière et E2E : le fil seulement, après déploiement de test. Pas dans un run.

## Structure
- `trust_layer/` : l'application (`app.py`, `proofs.py`, `timestamps.py`, `rekor.py`, `crypto.py`, `config.py`…) ; `routers/` pour les routes, `payments/` pour les fournisseurs de paiement.
- `signer/` : `tl_signer`, détient les clés privées, sans réseau.
- `scripts/` : déploiement, smoke tests, provisioning, vérificateur autonome `verify_proof.py` (stdlib seule).
- `tests/` : un `test_<module>.py` par module ; `conformance/` : vecteurs de la spec de preuve ; `docs/` : guides publics.
- Code neuf : une route dans `trust_layer/routers/`, un fournisseur de paiement dans `trust_layer/payments/` (classe de base `base.py`), un module de logique métier au niveau de `trust_layer/`, son test dans `tests/test_<module>.py`.

## Décisions d'architecture qui tiennent
- Clés privées uniquement dans `tl-signer` quand `TL_SIGNER_SOCKET` est posé ; le Trust Layer ne lit ni ne crée de fichier de clé dans ce mode (`signer/tl_signer.py`, `trust_layer/config.py`).
- La version se décide dans la PR (`trust_layer/__init__.py` + entrée `CHANGELOG.md`), jamais dans le script de déploiement ; le script ne pousse rien sur `main`, il pousse seulement le tag (`scripts/deploy_trust_layer_prod.sh`).
- Déploiement par étapes : standby d'abord, puis primaire, puis smoke test, retour arrière en cas d'échec (idem).
- Structure d'une preuve et algorithme de chaîne : définis par la spec externe `ark-forge/proof-spec` ; la modifier d'abord, puis les vecteurs (`CONTRIBUTING.md`).
- Parseurs de reçus PSP, analyseurs et cadres de conformité : classe de base abstraite + registre (`ROADMAP.md`).

## Conventions
- Commits : un titre court, clair, sujet puis effet ; numéro de version entre parenthèses quand le commit change la version (voir `git log`).
- Branches : `lot/<L>`, `cor/<L>-<n>`, `essai/<nom>`.
- Nommage : conventions du langage (PEP 8, ruff `N`) ; tests nommés par le comportement qu'ils vérifient.

## Ce qu'un agent ne fait jamais ici
- Déployer : seul `scripts/deploy_trust_layer_prod.sh` déploie, lancé par l'exploitant.
- Toucher la prod ou un secret (lecture, appel, copie) ; aucune donnée réelle dans un test ou un fichier versionné.
- Passer Stripe en mode live ni utiliser une clé `STRIPE_LIVE_*`.
- Pousser sur `main` ou créer un tag : `release.yml` part sur tout tag `v*`.
- Modifier le contenu existant de `proofs/` ou `data/` (données d'exécution, hors git).
- Régénérer les locks `requirements*.txt` sans raison : la CI compare chaque lock à son `.in`.
- Lancer `ruff --fix` ou reformater un fichier existant en masse.
