# Changelog

All notable changes to Trust Layer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [1.12.0] — 2026-09-24

### Added
- `tl-signer` (`signer/tl_signer.py`): a separate service that holds the private keys and signs over a Unix
  socket. Closed operations only (chain hash, reputation statement, JWS built by the signer, Rekor artifact),
  bounded inputs, no operation returns key material. Keys are born in the signer, one per node.
- Signer mode: with `TL_SIGNER_SOCKET` set, the Trust Layer reads and creates no key file, takes its public keys
  from the socket at startup, and refuses to start if its key is missing from the published history. Unset, the
  legacy `.pem` keys are used as before.
- Key history (`trust_layer/published_keys.json`): `/v1/pubkey` adds `kid`, `rekor_kid`, `keys` and `rekor_keys`;
  `/.well-known/did.json` lists every key, the node key first, and only keys not retired may assert.
- Proofs carry `arkforge_kid`, attestations and reputation scores `signature_kid`. The kid is added after the
  chain hash, like `arkforge_pubkey`.
- `scripts/verify_proof.py` picks the key a proof names (or, for older proofs, the key it carries) from the
  history, and refuses a key retired before the proof's date. Rekor entries are attributed to any published
  Rekor key of the history.

### Changed
- CTEF verdicts: the JWS header (`alg`, `kid`) is set by the signer, no longer a hardcoded `#key-1`.

## [1.11.4] — 2026-09-21

### Fixed
- Le script de déploiement n'installait jamais `requirements.txt` : les montées de dépendances étaient taguées sans
  atteindre la prod (`cryptography` 49.0.0, `setuptools` 82.0.1 et `anyio` 4.13.0 tournaient encore sur les deux
  nœuds). Chaque nœud installe désormais les dépendances dans le venv de son `ExecStart` avant le redémarrage, puis
  `scripts/check_requirements_installed.py` compare les épingles au venv ; un écart annule le déploiement. Les
  rollbacks réinstallent les dépendances du commit précédent. Le gate 4 teste sur les dépendances du commit à déployer.
- Ce déploiement applique enfin `cryptography` 50.0.0, `setuptools` 83.0.0 et `anyio` 4.14.2.

## [1.11.3] — 2026-09-21

### Security
- Le client Redis journalisait l'URL de connexion complète, mot de passe compris, à chaque démarrage du service.
  Seuls l'hôte, le port et la base sont écrits. Le filtre de données sensibles, posé sur les loggers et non sur
  les handlers, ne voit pas les loggers enfants comme `trust_layer.redis_client`.
- Script de déploiement : un déploiement dont les gates de sécurité manquent est refusé, au lieu d'un WARN (#43).
- `anyio` 4.13.0 → 4.14.2 (GHSA-5p39-cfhj-2xmp, critique : encodage IDNA 2003 dans `TLSStream`, usurpation de
  certificat possible sur les appels sortants ; GHSA-82r6-8w77-94w6).

## [1.11.2] — 2026-09-15

### Fixed
- Liens scanner vers la nouvelle page tarifs du site (`/{lang}/scanner-pricing.html`), `pricing.html` ne portant plus
  que le Trust Layer : `cancel_url` du checkout (`/v1/keys/setup`) et de l'essai (`/v1/keys/trial`), `upgrade_url`
  de repli de l'essai, et lien de reprise du mail de checkout abandonné selon `metadata.product`

## [1.11.1] — 2026-09-15

### Fixed
- Page preuve (`GET /v1/proof/{id}` en HTML) : la vue publique ne porte aucun frais de certification, et la page
  affichait pourtant « Payment verified independently by Stripe » pour toute preuve. Sans frais dans la preuve, plus
  de ligne paiement, de point de confiance Stripe ni de témoin Stripe
- La signature Ed25519 n'est plus rangée parmi les sources indépendantes (« Verification sources », clé d'ArkForge)
- « You do not need to trust ArkForge to verify this proof » remplacé par ce qui se vérifie sans ArkForge :
  l'horodatage RFC 3161 et l'entrée Sigstore Rekor
- « Service » et « Initiated by » lus aussi à la racine de la vue publique, où `seller` et `agent_identity` sont
  aplatis : la ligne Service était vide. Lignes techniques Payment ID et Buyer masquées quand elles sont vides

## [1.11.0] — 2026-09-15

### Added
- `POST /v1/proofs` (`{"proof_ids": [...]}`, 1 à 50 identifiants) : vues publiques groupées des preuves
  PROVE IT, comptées pour une seule lecture sur le seuil anti-abus de l'IP (100 par heure, partagé avec
  `GET /v1/proof/{id}`). Rejouer un score lit une trentaine de preuves : une par une, trois scores par heure
  bloquaient l'IP, pour ArkForge à la clôture comme pour un tiers qui vérifie
- Réservé aux preuves dont le `seller` est `corpus.arkforge.tech` ou `proveit.arkforge.tech`
  (`PROVEIT_PROOF_SELLERS`). Toute autre preuve, ou une preuve absente, vaut `null` : le lot ne dit pas si
  une preuve client existe. Pas d'incrément de `views_count`, pas de rendu HTML. Non documenté pour les clients

### Changed
- Journal d'accès aux preuves : une ligne par preuve lue, lot compris ; le compteur anti-abus avance d'une
  unité par requête

## [1.10.2] — 2026-09-15

### Fixed
- Page preuve (`GET /v1/proof/{id}` en HTML) : plus de « paid » ni « dispute-proof » pour toute preuve vérifiée,
  verdict « PROOF VERIFIED » ou « CHAIN HASH VERIFIED » selon l'horodatage, algorithme Merkle affiché pour les
  specs 3.0 et 3.1, plus de « date cannot be altered »
- `GET /v1/pricing` et `/.well-known/agent.json` : la signature Ed25519 est celle d'ArkForge, seuls l'horodatage
  RFC 3161 et Rekor sont indépendants. Plus de « 3 independent witnesses » ni « immutable », plus de QTSP inclus
- Page d'essai et preuves des rapports de conformité : « tamper-evident » au lieu de « tamper-proof »

## [1.10.1] — 2026-09-14

### Added
- `scripts/provision_challenge_key.py --profil calibration` : clé `internal` sans email
  (`proveit_calibration`, coffre `proveit.calibration_api_key`) pour les runs de référence des profils LLM
  de PROVE IT. Six runs dépassent le quota `free` de la clé de validation, et une clé distincte de celle de
  l'opérateur garde les DID de calibration hors de son historique de liaison

### Operations
- script seul, rien de servi par l'application. Le déploiement sert à faire relire au proxy
  `proveit.challenge_keys` après `provision_challenge_secret.py --allow-key-ref proveit_calibration` :
  émettre et autoriser la clé avant de déployer ce commit

## [1.10.0] — 2026-09-14

### Added
- `GET /v1/keys/identity` : le porteur d'une clé lit le DID lié à sa clé (`verified_did`, méthode, date)
  et son historique de liaison (`verified_did_history`). Identité seule : ni email, ni plan, ni référence
  de paiement. Consommateur : le service de saison PROVE IT (un DID par clé, DID liés à une même clé comptés
  comme un seul participant)

### Operations
- nouvelle route servie par l'application : déploiement requis (`deploy_trust_layer_prod.sh`)

## [1.9.3] — 2026-09-14

### Fixed
- `scripts/verify_proof.py` : des paires divulguées (`--disclose` ou bloc `disclosed`) sur une preuve
  sans engagements (spec < 3.0) produisent une ligne « selective disclosure » en FAIL. Avant, aucune
  ligne : un consommateur qui ne cherche que les FAIL lisait le silence comme une ouverture réussie

### Operations
- script de vérification tierce seul, rien de servi par l'application : aucun déploiement requis

## [1.9.2] — 2026-09-14

### Fixed
- `scripts/provision_challenge_secret.py` : `--allow-key-ref` et `--open` / `--close` relisent le
  coffre sur disque après écriture et échouent si la valeur a disparu. Le coffre réécrit tout son
  fichier depuis sa copie en mémoire, sans verrou : un autre écrivain passant juste après effaçait
  l'écriture sans erreur, et le script annonçait un succès. Cas grave : un `--close` perdu laissait
  la saison ouverte à toutes les clés. La cause (écriture non atomique du coffre) n'est pas corrigée ici

### Operations
- ce déploiement fait relire le coffre au proxy : les deux clés PROVE IT autorisées avant
  l'ouverture (`proveit_challenge`, `proveit_validation`) sont prises en compte

## [1.9.1] — 2026-09-14

### Security
- corpus PROVE IT : `X-Challenge-Secret` n'était filtré que sur l'hôte cible. Toute clé, y compris
  une clé obtenue par `/v1/keys/free-signup`, l'aurait reçu : le corpus privé était lisible par
  tous dès son DNS posé. Tant que la saison est fermée, le secret ne part plus qu'aux clés listées
  par empreinte sha256 dans `proveit.challenge_keys`. Seul `proveit.challenge_open = true` ouvre
  la saison ; un coffre illisible la laisse fermée. Empreinte et non ref : la ref d'une clé free
  (`free_signup_<email>`) se recrée par un tiers dès que la clé d'origine est désactivée
- cache d'idempotence : il était indexé sur `X-Idempotency-Key` seule. Une autre clé qui rejouait
  la même valeur recevait la réponse du premier appelant, sans aucun contrôle par appelant. Le
  cache est désormais propre à chaque clé. Effet du déploiement : les entrées en cache (24 h)
  ne sont plus retrouvées, un rejeu juste après ré-exécute l'appel une fois
- configuration : quand le coffre est lu, il fait foi pour `challenge_open` et `challenge_keys`,
  valeur vide comprise ; une variable d'environnement préexistante ne peut plus ouvrir la saison

### Added
- `scripts/provision_challenge_secret.py` : `--allow-key-ref <ref>` (ajoute l'empreinte de la
  clé active, jamais la clé), `--open` / `--close`
- `scripts/provision_challenge_key.py --profil validation` : clé `free` de l'agent de
  validation, ref `proveit_validation`, sans email

---

## [1.9.0] — 2026-09-14

### Security
- binding DID : la méthode qui a prouvé le contrôle (`challenge_response`, `oatr_delegation`)
  est enregistrée, et un changement de DID **ou de méthode** pousse l'ancien lien dans
  `verified_did_history`. Une délégation OATR ne remplace plus en silence une preuve par
  signature
- déploiement : le script ne pousse plus rien sur `main` (bump et CHANGELOG contournaient le
  check CI obligatoire). La version et le CHANGELOG se fixent dans la PR ; `--minor` et
  `--major` sont retirés ; seul le tag est poussé
- déploiement : l'ordre était inversé. Le script redémarrait d'abord le primary (VPS1, seul
  à servir `trust.arkforge.tech`, sans upstream de repli) en l'appelant « failover », puis le
  standby en l'appelant « primary ». Il lit désormais les rôles dans `failover_state.json`,
  refuse toute autre topologie, déploie le standby en premier avec canari, puis le primary
- déploiement : les gates tournaient sur l'arbre d'avant le `git pull`, et proof-spec /
  agent-client n'étaient jamais mis à jour. Les trois clones sont tirés en `--ff-only` avant
  les gates ; le gate CI vérifie le commit déployé, plus « le dernier run sur main » ; la santé
  exige la version attendue, pas seulement `status: ok`

### Added
- spec 3.1 : le bloc d'identité entre dans les champs engagés, toujours, un agent sans
  identité l'engageant à `null`. Jusqu'à 3.0 il était servi publiquement et engagé nulle
  part : hors racine Merkle, donc hors `hashes.chain`, hors signature Ed25519, donc hors
  jeton RFC 3161 et hors Rekor. L'émetteur pouvait le réécrire après ancrage sans qu'aucun
  témoin externe ne bouge
- `identity_consistent` engagé avec eux : c'est un jugement sur l'identité, l'ancrer à
  côté de ses trois voisins évite de reconstruire le même trou un champ plus à gauche
- `disclosed` dans la vue publique : les nonces du bloc, publiés, pour que n'importe qui
  ouvre l'identité et la recoupe avec l'engagement ancré
- `verify_proof.py` : témoin « agent identity » distinct, et une ligne explicite sur une
  preuve antérieure à 3.1 qui déclare une identité — le silence sur une affirmation non
  adossée se lit comme un accord
- vecteurs de conformité 13 et 14 de proof-spec 3.1

### Fixed
- les champs plats d'identité de la vue publique sont lus depuis la donnée engagée, plus
  depuis `parties` : éditer `parties` ne change plus rien de ce qu'un lecteur voit

### Changed
- `agent_identity_verified` vaut `True` ou `None`, jamais `False`, normalisé une seule
  fois à la source pour que la valeur engagée et la valeur servie ne puissent pas diverger
- `X-Agent-Identity` borné à 256 caractères, caractères de contrôle refusés (400). Depuis
  3.1 la valeur est engagée et publiée : elle est gravée, alors qu'elle était jusque-là
  nettoyable côté serveur. Borne choisie après mesure de la prod (2 identités, 27 car. max)

### Fixed (relecture §4.2)
- `verify_proof.py` rendait une trace d'exception au lieu d'un verdict sur un `disclosed`
  ou un engagement malformé. C'est à la fois la procédure qu'un tiers exécute et un gate
  bloquant du déploiement : dans les deux rôles une trace est pire qu'un échec. `strip_sha256`
  devient totale, `disclosed` est lu défensivement, et **tout témoin qui lève devient un
  échec** — la classe, pas les deux cas trouvés

---

## [1.8.2] — 2026-09-13

### Internal
- le dry-run annoncait la moitie de ce qu il ferait
- --host pose aussi l allowlist du corpus
- scrubber par valeur, provisionnement du secret par le coffre
- fermer la table de mutation et garder les noms de config des fautes de frappe
- secret dedie au corpus du challenge, distinct du secret interne

---

## [1.8.1] — 2026-09-13

### Fixed
- le binding ecrivait le challenge dans Redis et le relisait en memoire

### Internal
- ajouter fakeredis a l'extra test

---

## [1.8.0] — 2026-09-13

### Added
- engagements par champ (spec 3.0) + ancrage par lot Merkle
- rendre les ancrages externes vérifiables par un tiers
- émettre la clé du challenge par un chemin rejouable

### Fixed
- le smoke test de sécurité partait en Python-urllib et prenait un 403

### Tests
- couvrir les vecteurs spec 3.0 de proof-spec

### Internal
- durcissement du lot, du vérificateur et des chemins de sortie des nonces
- docs+mesure: réécrire la procédure de vérification, exercée en tiers sur un lot réel
- ne plus exposer le webhook secret Stripe via /v1/admin/smoke/setup
- mettre a jour setuptools avant pip-audit

---

## [1.8.0] — 2026-09-13

### Added
- spec 3.0 : `hashes.chain` devient la racine Merkle d'un engagement par champ,
  `sha256(champ || 0x00 || nonce || canonical_json(valeur))`, nonce de 32 octets
  frais par champ et par preuve. La preuve publique publie les engagements et
  aucune valeur : le tiers recalcule le hash ancré sans que `transaction_id` ni
  `buyer_fingerprint` soient exposés
- divulgation sélective : `GET /v1/proof/{id}/full` rend `commitment_nonces` et
  `chain_data` au propriétaire, `verify_proof.py --disclose` vérifie les triplets
  (champ, nonce, valeur) contre les engagements publiés. Aucune route nouvelle
- ancrage par lot : une requête RFC 3161 et une entrée Sigstore Rekor par lot
  (100 preuves ou 10 min) sur la racine Merkle, au lieu d'une par preuve. Chaque
  preuve embarque son chemin d'inclusion et les artefacts d'ancre
- `trust_layer/merkle.py` : RFC 6962 pour les deux niveaux, croisé contre une
  preuve d'inclusion Sigstore réelle
- `batch_anchor` exposé sur `GET /v1/proof/{id}/verify`
- `POST /v1/admin/batch/close` (X-Internal-Secret) : ancre le lot en attente sans
  attendre la taille ni l'âge. Utilisé par le gate de déploiement, qui doit
  observer un ancrage réel — un gate qui cesse de mesurer l'ancrage est un leurre
- reprise au démarrage d'un lot interrompu en pleine fermeture : il est déplacé
  dans `batches/closing/` avant l'ancrage et n'en sort qu'une fois les preuves
  estampillées
- page de preuve : état « ANCHORING IN PROGRESS » tant que le lot n'est pas fermé,
  au lieu d'un « timestamp not yet available » qui se lit comme une panne

### Changed
- le lot est horodaté au plan le plus exigeant qu'il contient : une preuve
  `platform` route tout le lot vers DigiCert. Le routage TSA par plan a quitté le
  chemin par preuve avec l'ancrage par lot
- `TRUST_LAYER_BASE` surchargeable dans `verify_proof.py`, pour jouer la
  procédure telle quelle contre une autre instance
- README, guide et quick-reference réécrits : le one-liner de vérification
  publié recalculait la formule des valeurs et répondait `TAMPERED` sur une
  preuve publique honnête

### Internal
- une preuve dont le lot n'est pas fermé est `pending` et le dit, jamais
  `TAMPERED` ; un chemin d'inclusion invalide ne se confond plus avec une attente
- `verify_proof.py` rend un verdict, jamais une trace Python, sur une preuve
  malformée (chemin tronqué, entrée non hexadécimale, engagement absurde)
- un `tree_size` surévalué est refusé : la longueur du chemin d'inclusion est
  déterministe et se vérifie, là où le seul parcours atteint la vraie racine et
  s'arrête tôt en validant une forme d'arbre qui n'a jamais existé
- les nonces d'engagement ne sortent que par `/v1/proof/{id}/full` : les réponses
  du proxy sont débarrassées des champs préfixés `_`
- le lot en attente vit sur disque en écriture atomique et se ferme sur un tic de
  fond indépendant du trafic
- 724 tests (+90)

---

## [1.7.2] — 2026-09-11

### Fixed
- Phase 3b (MCP PyPI sync) uses a dedicated venv, not bare python3

### Internal
- bump cryptography 49.0.0->50.0.0, setuptools 82.0.1->83.0.0

---

## [1.7.1] — 2026-09-11

### Added
- _writes_blocked() dissocie le blocage d ecriture du role de noeud

### Fixed
- smoke test invocation — drop stale --ovh-host flag, pass internal secret
- run Gate 4 tests with the project venv, not bare python3
- stop leaking X-Internal-Secret to arbitrary proxy targets
- 5 mails identiques a la meme adresse le meme jour
- /health derive de writes/role, plus de _is_failover_mode trompeur
- chemin du drapeau failover surchargeable par FAILOVER_STATE_FILE

### Internal
- ajoute redis, absent du fichier alors que le code le charge

---

## [1.3.71] — 2026-05-27

### Fixed
- unpack submit_hash tuple in recovery + poll proof status before TSR check
- HEAD 404 body mismatch + smoke test retry for TSA fallback
- replace get_event_loop() with async def in test_stripe_no_key
- upgrade starlette 1.0.0→1.1.0 and idna 3.15→3.16

---

## [1.3.70] — 2026-05-26

### Fixed
- add #trust hash to Trust Layer pricing URLs

---

## [1.3.69] — 2026-05-25

### Added
- add POST /create-checkout-session endpoint

### Fixed
- deactivate orphan trial keys on paid upgrade + track trial_to_paid conversions
- make pip-audit blocking — skip editable packages instead of continue-on-error
- patch STRIPE_LIVE_KEY in bot-UA checkout test

---

## [1.3.69] — 2026-05-15

### Fixed
- strengthen bot-UA checkout test assertions (== live key, not != test key)
- add bot-UA live-mode test coverage for /v1/keys/trial endpoint

---

## [1.3.68] — 2026-05-14

### Fixed
- stop bot-UA guard from silently blocking real customers in checkout

---

## [1.3.67] — 2026-05-14

### Fixed
- route Scanner Pro to separate Stripe product/price

---

## [1.3.66] — 2026-05-14

### Fixed
- trial endpoint respects product=scanner + admin alert on pricing misconfigured

---

## [1.3.65] — 2026-05-14

_(no user-facing changes)_

---

## [1.3.64] — 2026-05-14

### Added
- add GET /trial landing page for badge and CLI CTAs

---

## [1.3.63] — 2026-05-13

### Fixed
- break circular upgrade_url fallback pro-signup→pricing

---

## [1.3.62] — 2026-05-13

### Fixed
- expires_at 14d→23h + Stripe session for existing trials

---

## [1.3.61] — 2026-05-13

### Documentation
- add Free Tier badge + signup CTA

---

## [1.3.60] — 2026-05-13

### Fixed
- add is_external safety net to prevent LIVE customer creation from non-external visitors

---

## [1.3.59] — 2026-05-13

### Added
- card-free 14-day trial via POST /v1/keys/trial

### Fixed
- upgrade urllib3 (CVE-2026-44431, CVE-2026-44432), pytest (CVE-2025-71176), and refresh dependency versions
- add OVH IPv6 to _INTERNAL_IPS, 'verify'/'flow-' to test-email guards, burst rate-limit 3/10min

---

## [1.3.58] — 2026-05-12

_(no user-facing changes)_

---

## [1.3.57] — 2026-05-11

### Fixed
- add diagnostic event_type+sig_prefix to signature failure logs

---

## [1.3.56] — 2026-05-11

### Fixed
- harden internal IP mode guard + _is_test_email coverage

---

## [1.3.55] — 2026-05-11

_(no user-facing changes)_

---

## [1.3.54] — 2026-05-10

### Fixed
- force test mode for diagnostic/internal emails
- use body referrer for visitor classification in /v1/keys/setup

---

## [1.3.53] — 2026-05-09

### Added
- add is_external visitor attribution to checkout funnel events

### Fixed
- email delivery monitoring + per-email rate limiting

---

## [1.3.52] — 2026-05-09

_(no user-facing changes)_

---

## [1.3.51] — 2026-05-07

### Fixed
- include y as vowel in gibberish detection to reduce false positives

---

## [1.3.50] — 2026-05-07

### Fixed
- anti-spam email validation + 24h expiry + Link payments

---

## [1.3.49] — 2026-05-05

### Added
- public /v1/demo endpoint for prospect conversion

---

## [1.3.48] — 2026-05-05

### Added
- non-repudiation positioning — tagline + CTA banner

---

## [1.3.47] — 2026-05-05

### Fixed
- force test mode for RFC 2606 reserved email domains at source

---

## [1.3.46] — 2026-05-05

### Tests
- add scanner_pro_subscription routing regression test

---

## [1.3.45] — 2026-05-04

### Fixed
- handle scanner_pro_subscription in checkout webhook handler
- fix dns.resolver import scope in _verify_mx

---

## [1.3.44] — 2026-05-03

### Fixed
- add DNS MX validation to reject fake email domains
- add DNS MX validation to reject fake email domains

---

## [1.3.43] — 2026-05-03

_(no user-facing changes)_

---

## [1.3.42] — 2026-05-03

### Fixed
- update test email domain to non-blocked domain after disposable email blocklist
- route Scanner Pro through Checkout Sessions with real 14-day trial + block disposable emails

---

## [1.3.41] — 2026-05-03

### Fixed
- add honeypot anti-bot check to signup endpoints
- add MCP_SCAN_PINGS_LOG to config exports
- add rate limiting to /v1/keys/setup endpoint

### Documentation
- add CTEF constraint_evaluation mapping + tier_upgrade_proof v0.3.2 notes

### Internal
- upgrade dependencies — cryptography 46→47, fastapi 0.135→0.136, stripe 15.0→15.1, uvicorn 0.42→0.46

---

## [1.3.41] — 2026-05-02

### Added
- CTEF cross-implementation reference in user-guide: constraint_evaluation field mapping (AgentGraph→ArkForge), `no_critical_findings` enforcement gate, `tier_upgrade_proof` composable envelope example
- document v0.3.2 alignment: depth-first proof-stripping, canonical-bytes-diff fixture, 3 constraint_evaluation test vectors (within-limit/near-miss/exceeded)

---

## [1.3.40] — 2026-04-24

### Fixed
- add UTM tracking to README and email template links

---

## [1.3.39] — 2026-04-24

### Fixed
- add upgrade_url to free-signup API response
- add UTM tracking to Stripe checkout cancel, portal return, and abandoned checkout email URLs

---

## [1.3.38] — 2026-04-23

### Fixed
- checkout abandonment recovery + email resolution fallback

---

## [1.3.37] — 2026-04-23

### Added
- record web signups in MCP registration_log for register_free_key_calls_web

### Fixed
- add Pro upgrade CTA to free welcome email

---

## [1.3.36] — 2026-04-16

### Fixed
- filter internal/test scans from cta_impression metrics

---

## [1.3.35] — 2026-04-16

_(no user-facing changes)_

---

## [1.3.34] — 2026-04-14

### Added
- add POST /api/register endpoint for MCP phone-home registration

---

## [1.3.33] — 2026-04-10

### Added
- log tool_names and plan in scan_events.jsonl

---

## [1.3.32] — 2026-04-09

_(no user-facing changes)_

---

## [1.3.31] — 2026-04-09

### Fixed
- dynamic FAILOVER_MODE via state file — eliminates stale systemd env var

---

## [1.3.30] — 2026-04-09

### Fixed
- add User-Agent to all raw urllib requests
- add User-Agent header to prevent 403 from empty UA filter
- always return dict from req() to prevent AttributeError
- always expose mode/write_enabled, harden smoke test
- always expose mode and write_enabled fields

---

## [1.3.29] — 2026-04-09

### Added
- add server-side scan counter to /v1/stats + scan_events.jsonl

---

## [1.3.28] — 2026-04-08

### Added
- add POST /v1/contact enterprise demo request endpoint

---

## [1.3.27] — 2026-04-08

### Fixed
- use noreply@arkforge.tech as SMTP from address — arkforge.fr not verified on Resend

---

## [1.3.26] — 2026-04-07

### Fixed
- add Rekor independent verify URL to proof email
- Phase 3b — capturer stderr twine, revert on failure, idempotent on already-exists

---

## [1.3.25] — 2026-04-03

### Added
- sync arkforge-mcp à chaque livraison TL (Phase 3b)

### Fixed
- pricing URL arkforge.fr → arkforge.tech

---

## [1.3.24] — 2026-04-03

### Added
- add _links.pricing CTA in JSON responses for scan-to-pricing conversion

---

## [1.3.23] — 2026-04-03

_(no user-facing changes)_

---

## [1.3.22] — 2026-04-03

### Added
- NIST AI RMF 1.0 + SOC 2 Readiness frameworks — v1.3.23

---

## [1.3.23] — 2026-04-03

### Added
- **NIST AI RMF 1.0 compliance framework** — `POST /v1/compliance-report` accepts `"framework": "nist_ai_rmf"`.
  Maps Trust Layer proof fields to 7 subcategories across GOVERN, MAP, MEASURE, MANAGE:
  - GOVERN 1.1 Risk Policies (not_applicable), MAP 1.1 Context (spec + agent_identity),
    MAP 5.2 Risk Tracking (chain hash), MEASURE 1.1 Measurement (integrity),
    MEASURE 2.5 Monitoring (RFC 3161), MANAGE 1.3 Treatment (chain + integrity),
    MANAGE 4.1 Monitoring (proof_id + timestamp)
- **SOC 2 Readiness framework** — `POST /v1/compliance-report` accepts `"framework": "soc2_readiness"`.
  Maps to 6 AICPA Trust Service Criteria:
  - CC6.1 Logical Access (buyer_fp + seller), CC6.7 Transmission Integrity (all 3 hashes),
    CC7.2 Security Monitoring (RFC 3161), PI1.1 Completeness (integrity),
    PI1.2 Accuracy (proof_id + timestamp + fee), A1.1 Availability (not_applicable)
  - Prominent disclaimer: readiness evidence only, not a formal SOC 2 audit opinion
- 27 new tests — map_proof + generate_report + endpoint integration for both frameworks.
  522 → 549 total, 0 regressions.
- `README.md` — compliance reports section listing all 4 frameworks with curl example.
- `docs/user-guide.md` — NIST AI RMF and SOC 2 Readiness sections with criteria tables.
- `docs/quick-reference.md` — compliance endpoint updated to list all 4 frameworks.

### Changed
- `POST /v1/compliance-report` docstring: lists all 4 supported frameworks.
- `docs/user-guide.md`: "More frameworks planned" note replaced with full list.

---

## [1.3.21] — 2026-04-03

### Added
- **ISO/IEC 42001:2023 compliance framework** — `POST /v1/compliance-report` now accepts `"framework": "iso_42001"`.
  Maps Trust Layer proof fields to 6 AI Management System clauses:
  - § 6.1 Risk and Opportunity Management — `hashes.chain` presence
  - § 8.2 AI Risk Assessment — proof integrity verifiability
  - § 8.4 AI System Lifecycle Documentation — `spec_version` + `parties.agent_version`
  - § 9.1 Monitoring, Measurement and Evaluation — RFC 3161 verified timestamp
  - § 9.2 Internal Audit — cryptographic audit trail integrity
  - § 10.1 Nonconformity and Corrective Action — `not_applicable` (organisational obligation)
- 19 new tests — `ISO42001Framework.map_proof`, `generate_report`, endpoint integration.
  504 → 523 total, 0 regressions.
- `docs/user-guide.md` — full ISO 42001 section with curl + Python examples, clause coverage table.
- `docs/quick-reference.md` — compliance endpoint updated to list both frameworks.

### Changed
- `POST /v1/compliance-report` docstring updated: lists `eu_ai_act, iso_42001` as supported frameworks.
- Error message for `unknown_framework` now dynamically lists all registered frameworks (including `iso_42001`).

---

## [1.3.20] — 2026-04-03

### Fixed
- update_changelog.py reçoit HEAD + label séparé — le tag n'existe pas encore au moment de l'appel

### Documentation
- fix proof index version reference (v1.4.0 → v1.3.18) + minor README/deps updates

---

## [1.3.19] — 2026-04-03

### Changed
- **Proof index: DualWrite resilience** — `DualWriteProofIndex` replaces pure `RedisProofIndex` when Redis is available. JSONL is now always written first (durable source of truth); Redis is written second (fast `ZRANGEBYSCORE` queries). If Redis fails mid-write, the JSONL entry is already committed — no data loss.

### Added
- **Automatic JSONL→Redis reconciliation** — two background daemon threads handle sync without operator intervention:
  - *Startup reconciliation*: full JSONL replay into Redis on every service (re)start. Recovers from Redis data loss after restart.
  - *Periodic reconciliation*: re-replays the last 25 hours of JSONL into Redis every 5 minutes. Recovers from Redis outages that occur while the service is running, without requiring a service restart.
- `DualWriteProofIndex.reconcile(since_unix=None)` — callable method for manual or scripted reconciliation.
- `backfill_proof_index.py --from-jsonl` mode — replays JSONL directly into Redis (faster than scanning proof files). Supports `--since ISO8601` for incremental reconciliation.
- Ops documentation in `docs/user-guide.md` — resilience model, reconciliation triggers, manual commands.

---

## [1.3.18] — 2026-04-03

### Added
- **`POST /v1/assess`** — MCP server security posture assessment. Analyzes a server manifest for dangerous capability patterns (`PermissionAnalyzer`: filesystem write, code execution, env access, network), tool drift (`DescriptionDriftAnalyzer`: additions/removals/description changes via `difflib`), and version regressions (`VersionTrackingAnalyzer`). Returns `risk_score` (0–100), categorized findings, and baseline diff. Baseline stored per `(api_key, server_id)` in `data/mcp_baselines/`. Rate limit: 100 calls/day per API key.
- **`POST /v1/compliance-report`** — EU AI Act compliance report. Aggregates certified proofs for an API key over a date range and maps them to 6 articles: Art. 9 (risk management), Art. 10 (data governance — not applicable), Art. 13 (transparency), Art. 14 (human oversight), Art. 17 (quality management), Art. 22 (record-keeping). Returns per-article coverage status (`covered`/`partial`/`gap`/`not_applicable`) with evidence summaries and a gaps list.
- **`ProofIndexBackend` ABC** — pluggable proof index abstraction. `RedisProofIndex` (ZADD/ZRANGEBYSCORE, 90-day TTL) + `FileProofIndex` (JSONL append, `threading.Lock`) fallback. Powers date-range queries for compliance reports without scanning all proof files.
- **`scripts/backfill_proof_index.py`** — one-shot migration to index proofs created before v1.3.18.
- **APIRouter pattern** — first use of `fastapi.APIRouter` in the codebase. New routes are isolated modules under `trust_layer/routers/`. Existing `app.py` routes are untouched.

---

## [1.3.17] — 2026-04-01

### Documentation
- ROADMAP updated to reflect implemented features: agent identity, DID binding, Platform plan, proof privacy model (`/v1/proof/{id}/full`), `/v1/proof/{id}/verify` endpoint.

---

## [1.3.16] — 2026-04-01

### Added
- Platform plan TSA routing unit tests: Platform keys skip FreeTSA, fall back to Sectigo; non-platform plans retain FreeTSA-first behaviour.
- E2E integration tests for Platform plan: key prefix detection, plan propagation to `submit_hash`, DigiCert TSA confirmed on live proof.

---

## [1.3.15] — 2026-03-31

### Added
- **Platform plan** — 599 EUR/month, 500,000 proofs/month, for platforms and AI integrators. API key prefix `mcp_plat_`. Overage opt-in at 0.002 EUR/proof.
- **DigiCert-first TSA routing for Platform keys** — Platform API keys skip FreeTSA and use DigiCert as primary timestamp authority. FreeTSA is a community service with no SLA; DigiCert is WebTrust-certified with enterprise-grade reliability. Fallback chain: DigiCert → Sectigo (unchanged). All other plans retain FreeTSA-first behaviour.
- Platform plan exposed in `GET /v1/pricing`.
- Stripe product + price IDs (live and test) added to vault and loaded via `config.py`.

---

## [1.3.6] — 2026-03-26

### Changed
- Upgrade stripe 14.4.1 → 15.0.0. Adapted to `StripeObject` no longer inheriting from `dict`: webhook handler uses dot notation (`event.id`, `event.type`, `event.livemode`, `event.data.object.to_dict()`); payment provider uses `customer.invoice_settings` dot notation. Updated test mocks accordingly.

---

## [1.3.2] — 2026-03-24

### Added
- `parties.did_resolution_status` field in proof receipts. `"bound"` when `agent_identity` is a cryptographically verified DID bound via Ed25519 challenge-response or OATR delegation at registration time. `"unverified"` when `agent_identity` is caller-declared without cryptographic verification. Absent if no `agent_identity` is provided.

---

## [1.3.1] — 2026-03-24

### Changed
- `GET /v1/proof/{id}` now includes `agent_identity` and `seller` in public responses. `buyer_fingerprint` remains authenticated-only. Third-party auditors and WG members can verify agent identity without API key access.

---

## [1.3.0] — 2026-03-16

### Changed
- `GET /v1/proof/{id}` no longer exposes `provider_payment` details (receipt URL, parsed fields), `parties`, `certification_fee`, `buyer_reputation_score`, or `buyer_profile_url` in public responses. Only `receipt_content_hash` and `verification_status` remain visible in `provider_payment`.

### Added
- `GET /v1/proof/{id}/full` — authenticated endpoint (API key required, owner only). Returns the complete proof including payment details, parties, and certification fee. Ownership verified via `sha256(api_key) == parties.buyer_fingerprint`.

### Security
- Payment amounts, Stripe receipt URLs, parsed payment fields, buyer/seller identities, and reputation scores are no longer publicly visible on `GET /v1/proof/{id}`.

---

## [1.2.3] — 2026-03-11

### Fixed
- CI pipeline: validate release workflow produces green run after v1.2.1/v1.2.2 CHANGELOG commit fix.

---

## [1.2.2] — 2026-03-11

### Fixed
- CI release: CHANGELOG commit moved to deploy script (pre-tag) — avoids branch protection conflict during CI.
- CI fallback PR path for CHANGELOG commit when API commit is blocked.

---

## [1.2.1] — 2026-03-11

### Security
- Dependency update: cryptography 43.0.0 → 46.0.5 — patches 3 Dependabot CVEs (cee19b8)

### Tests
- Conformance: branch chain_hash by `algorithm` field (legacy vs canonical_json) (b28ee18)

---


## [1.2.0] — 2026-03-10

### Breaking Changes
- **Chain hash algorithm changed for spec_version 1.2 / proof-spec 2.1.**
  The chain hash is now computed over a canonical JSON dict (sorted keys) instead of a raw string concatenation. This eliminates preimage ambiguity when field values contain separator characters.
  Proofs issued before v1.2.0 (spec_version 1.1) continue to verify correctly via the legacy path in `verify_proof_integrity()`.

### Security
- **CRITICAL — chain hash preimage ambiguity (CVE-equivalent).**
  String concatenation `request_hash + response_hash + payment_intent_id + ...` allowed crafted values to produce collisions. Fixed by switching to `sha256(canonical_json({...}))` for spec_version ≥ 1.2.

### Added
- `proof-spec v2.1.0` alignment: `verify_proof_integrity()` routes by `spec_version` field (1.1/2.0 → legacy, 1.2/2.1 → canonical_json).
- Conformance test suite `tests/test_spec_conformance.py`: branches chain hash computation by `algorithm` field in test vectors. 27/27 vectors pass.

---

## [1.1.20] — 2026-03-09

### Security
- Proof abuse auto-block: `proof_abuse:{ip}` checked in Redis at the top of `get_proof()`, returns HTTP 429 immediately (previously only logged).
- Dependency pinning: `requirements.txt` now uses `==` exact versions (`pip freeze`); `requirements-dev.txt` separated. Gardien Check 2 covers CVEs via `pip-audit`.
- SAST: `nosec B104` annotations on intentional host bindings (`0.0.0.0`).

---

## [1.1.19] — 2026-03-09

### Fixed
- Templates: footer link `arkforge.fr` → `arkforge.tech` (domain migration).

---

## [1.1.18] — 2026-03-09

### Fixed
- All internal URLs and redirect targets migrated `arkforge.fr/trust` → `arkforge.tech/trust` (Stripe success/cancel/return URLs, nginx redirects).

---

## [1.1.17] — 2026-03-09

### Fixed
- Domain migration `arkforge.fr` → `arkforge.tech` for all public-facing URLs.

---

## [1.1.16] — 2026-03-08

### Fixed
- Welcome email: replaced generic text with actionable first-proof example for free tier users.
- CI gate: fallback to recent runs if no run directly on `main` (handles post squash-merge PRs).

### Documentation
- README rewrite: removed internal TSA provider names; public-facing language only.

---

## [1.1.15] — 2026-03-07

### Documentation
- Mode C (`extra_headers`) usage guide, Redis env var reference, systemd `--workers 4` example.

---

## [1.1.14] — 2026-03-06

### Added
- Redis hot path rate limiting (atomic `INCR + EXPIRE`): correct shared state across multiple uvicorn workers. In-memory fallback if Redis unavailable.
- Multi-worker readiness: shared rate limit state via Redis.

---

## [1.1.13] — 2026-03-06

### Changed
- Removed daily cap for all plans (Free/Pro/Enterprise). Monthly quota only — no per-day rate restriction.

---

## [1.1.12] — 2026-03-06

### Added
- Dynamic daily cap per plan: Free=100, Pro=500, Enterprise=5,000 proofs/day.

---

## [1.1.11] — 2026-03-06

### Documentation
- `extra_headers`: forwarding credentials to target APIs documentation.
- Proxy limits: full section (timeout, payload size, methods, format, daily cap).

---

## [1.1.10] — 2026-03-06

### Added
- `extra_headers` hardening: strict header allowlist, hop-by-hop filtering, dogfooding via certified GitHub comments.

---

## [1.1.9] — 2026-03-06

_(internal version bump — no user-facing changes)_

---

## [1.1.8] — 2026-03-06

### Fixed
- Removed pay-per-use pricing model (€0.10/proof): billing now subscription-only.
- Free tier test keys updated; test suite aligned.

### Security
- SSRF expansion: CGNAT ranges, IPv4-mapped IPv6, 6to4 added to `_PRIVATE_NETWORKS` blocklist.

### Documentation
- Security: uvicorn `127.0.0.1` binding rationale, `pip-audit` integration, network exposure model.

---

## [1.1.7] — 2026-03-05

### Added
- Transactional email migrated from OVH SMTP to Resend (better deliverability, API-based).

---

## [1.1.6] — 2026-03-05

### Fixed
- Smoke tests: use `@smoke.invalid` email addresses to prevent real SMTP delivery during test runs.

---

## [1.1.4 – 1.1.5] — 2026-03-05

### Security
- API keys encrypted at rest with Fernet (AES-128). `KEYS_FERNET_KEY_FILE` env var controls key path. 7-year retention.

---

## [1.1.3] — 2026-03-05

### Added
- Staged blue/green rollout via HA infra (failover-first strategy).
- Smoke test suite: 5 post-deploy validation sections.

### Fixed
- Versioning unified: `__init__.py` auto-bumped by deploy script.
- Rollback: `git reset --hard` + post-rollback verification.

### Documentation
- User guide: subscription lifecycle, billing portal, email alerts.

---

## [1.1.1 – 1.1.2] — 2026-03-05

_(initial 1.1.x series — internal stabilisation)_

---

## [0.5.4] — 2026-03-05

### Added
- Stripe webhooks: `invoice.paid` and `invoice.payment_failed` handlers.
