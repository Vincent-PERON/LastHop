# Checklist de durcissement du déploiement

Cocher chaque ligne avant la mise en production.

## Hôte et réseau
- [ ] Hôte à jour, accès SSH par clé, Docker non exposé sur TCP.
- [ ] Pare-feu hôte : entrant 80/443 uniquement (depuis les réseaux d'administration si possible) ; **aucun** port 5432/6379 publié.
- [ ] Pare-feu hôte : sortant du conteneur `worker` limité à UDP/161 vers les IP des équipements + DNS ; sortant de `api` limité à l'IdP (HTTPS).
- [ ] Sur chaque équipement : SNMPv3 authPriv, compte lecture seule, **ACL source = IP de l'hôte LastHop** (voir README, exemples au lot b).

- [ ] `snmp_allowed_cidrs` renseigné avec les seuls réseaux de management (jamais `0.0.0.0/0`, refusé) ; `snmp_v2c_enabled` laissé à `false` sauf nécessité.
- [ ] Profils SNMP : SHA-256+/AES, `allow_legacy_algos` uniquement pour les équipements qui ne supportent pas mieux (revue trimestrielle des profils `legacy`).
- [ ] Rotation périodique de la clé maître (`python -m app.cli reencrypt`) et des clés SNMP (`PUT /api/v1/credentials/{id}`).

- [ ] Pare-feu hôte : le `worker` sort uniquement vers UDP/161 (équipements), DNS (résolveur interne) et HTTPS `standards-oui.ieee.org` (ou importer l'OUI hors ligne et fermer cette sortie).
- [ ] `retention_days` validé avec le DPO (association poste ↔ IP ↔ port = donnée personnelle) ; intervalle de collecte adapté au parc (`poll_interval_s`).
- [ ] Vue SNMP des équipements : inclure ARP (`ipNetToMedia`/`ipNetToPhysical`), BRIDGE/Q-BRIDGE, LLDP, ENTITY ; sur Cisco, les contextes `vlan-<id>` (v3) ou `community@<id>` (v2c).

- [ ] Temps réel : `realtime_timeout_s` adapté (30 s par défaut) ; surveiller le service `worker-rt` (file `realtime`) ; limiter les opérateurs au strict nécessaire (chaque recherche est auditée).
- [ ] Reverse proxy : le flux SSE (`/api/v1/realtime/*/events`) ne doit être ni mis en tampon ni coupé (Caddyfile fourni : `flush_interval -1`) ; vérifier tout équilibreur ou WAF placé devant.

- [ ] Sauvegardes : pare-feu hôte — le `worker` sort aussi en **TCP/22** (ou le port SSH choisi) vers les équipements, rien d'autre ; compte SSH **dédié, lecture seule**, ACL source = hôte LastHop ; empreintes SSH comparées avec l'équipement avant approbation.
- [ ] Sauvegardes : les configurations sont des données très sensibles — sauvegardes de la base **chiffrées**, copie de `secrets/master_keys.json` séparée ; revoir périodiquement l'audit (`backup.view_raw`, `device.ssh_trust`) ; `backup_retention_days` validé.
- [ ] Sauvegardes : tester la restauration d'une configuration sur un équipement de laboratoire (LastHop ne restaure pas : il sauvegarde).

## TLS et en-têtes
- [ ] `SITE_ADDRESS` = nom DNS réel, certificat valide (ACME ou PKI interne), TLS ≥ 1.2 (réglé dans le Caddyfile).
- [ ] HSTS actif ; vérifier avec un scanner (ex. testssl.sh) : pas de TLS 1.0/1.1.
- [ ] CSP du front sans `unsafe-inline`/`unsafe-eval` ; CORS limité à `LASTHOP_FRONTEND_ORIGIN` (jamais `*`, refusé par la configuration).
- [ ] `LASTHOP_ENV=prod` (refuse un IdP non HTTPS).

- [ ] Front : servi **uniquement** derrière le proxy (CSP, HSTS, `X-Frame-Options`) ; vérifier avec `npm run csp-preview` après toute modification des dépendances (aucune violation `style-src`/`script-src`).
- [ ] Front : `npm audit` à 0 en CI ; mises à jour via Renovate ; ne jamais ajouter `unsafe-inline` à la CSP (corriger la bibliothèque ou son usage).

## Identité
- [ ] OIDC avec **MFA imposée côté IdP** (Keycloak : flux d'authentification ; Entra : accès conditionnel). Si l'IdP expose `acr`, renseigner `LASTHOP_OIDC_REQUIRED_ACR`.
- [ ] Groupes IdP `lasthop-admins/operators/viewers` créés ; `lasthop-admins` = super admin (profils SNMP/SSH, sauvegardes, paramètres, audit, tokens) : membres réduits au strict minimum.
- [ ] `redirect_uri` du client OIDC = URL exacte du callback ; PKCE S256 requis ; pas de flux implicite.
- [ ] Revue périodique des tokens d'API (`GET /api/v1/tokens?all=true`) ; durée de vie ≤ 90 jours.

## Secrets
- [ ] `./scripts/gen-secrets.sh` exécuté sur l'hôte ; dossier `secrets/` en 0700 propriétaire root/déploiement, **hors sauvegarde non chiffrée**.
- [ ] `secrets/master_keys.json` sauvegardé séparément de la base (coffre) ; sans elle, les identifiants SNMP sont irrécupérables.
- [ ] Rotation : ajouter une clé `k2`, la déclarer `active`, conserver `k1` jusqu'au re-chiffrement (outil au lot b).
- [ ] `.env` et `secrets/` absents de git (`git ls-files | grep -E '^(\.env|secrets/)'` ne doit rien retourner hors README).

## Données
- [ ] Sauvegarde PostgreSQL chiffrée (pg_dump + chiffrement), test de restauration documenté.
- [ ] Copie de l'audit vers un SIEM/syslog (hors base) ; `python -m app.cli audit-verify` planifié (quotidien) avec alerte si code ≠ 0.
- [ ] Rétention définie (défaut 90 jours) et validée avec le DPO ; information des personnes si requis.
- [ ] Optionnel : TLS Postgres/Redis (`LASTHOP_DB_SSL_CA_FILE`, `LASTHOP_REDIS_TLS_CA_FILE`) avec PKI interne.

## Conteneurs et supply chain
- [ ] Images construites par la CI, scannées Trivy (HIGH/CRITICAL bloquants), épinglées par digest.
- [ ] `pip-audit`, `bandit`, `semgrep` verts ; Renovate actif et PR de sécurité traitées sous 7 jours.
- [ ] `docker compose ps` : tous `healthy` ; `docker inspect` confirme `ReadonlyRootfs=true` et `CapDrop=[ALL]` pour api/worker/beat.

## Exploitation
- [ ] Logs JSON centralisés ; vérifier l'absence de communities/clés/tokens (`grep -ri community`).
- [ ] Alertes : échecs d'authentification en rafale, refus `authz.denied`, 5xx, rupture de chaîne d'audit.
- [ ] Procédure de mise à jour : `git pull` → CI verte → `docker compose build` → `docker compose up -d` (le service `migrate` applique Alembic) → vérifier `/healthz`.
