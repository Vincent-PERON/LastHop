# LastHop

Application web d'**IP/MAC Learning** et de **Real-Time Location** (équivalent des fonctions IMC de HPE), sécurisée par conception.
Avancement : **lots (a) à (f)** terminés (socle sécurisé ; inventaire, SNMP ; topologie L2 ; learning ; temps réel ; interface Vue 3). Plan complet : [PROPOSITION.md](PROPOSITION.md).

| Lot | Contenu | État |
|---|---|---|
| a | Socle, OIDC, RBAC, audit immuable, crypto, compose durci | ✅ |
| b | Inventaire, profils SNMP, découverte, drivers | ✅ |
| c | Topologie L2 | ✅ |
| d | Learning | ✅ |
| e | Real-time location | ✅ |
| f | Front Vue 3 | ✅ |
| g | Tests snmpsim, CI de sécurité complète | à faire |

## Commandes

```bash
./scripts/gen-secrets.sh                                   # génère les secrets locaux (jamais commités)
docker compose -f docker-compose.test.yml run --rm --build tests   # tests (Postgres 16 + Redis réels) + couverture
cp .env.example .env && $EDITOR .env                       # renseigner domaine et IdP, puis écrire secrets/oidc_client_secret
docker compose up -d --build                               # proxy, front, api, worker, beat, redis, postgres (+ migrate)
```

Qualité : `ruff check`, `ruff format`, `mypy app`, `bandit -r app`, `pip-audit` (voir `.github/workflows/ci.yml`).

## API du lot (a)

| Route | Rôle minimum | Description |
|---|---|---|
| `GET /api/v1/auth/login` → `/callback` | public | Connexion OIDC (code + PKCE) |
| `GET /api/v1/auth/me`, `POST /api/v1/auth/logout` | authentifié | Profil + jeton CSRF ; fin de session |
| `POST/GET/DELETE /api/v1/tokens` | super admin | Tokens d'API à portée limitée (affichés une seule fois) |
| `GET /api/v1/audit`, `/audit/verify` | admin | Consultation et vérification de la chaîne d'audit |
| `GET/PUT /api/v1/settings` | admin | Paramètres (v2c désactivé par défaut, rétention, concurrence…) |
| `GET /api/v1/openapi.json` | authentifié | Schéma OpenAPI (pas de `/docs` public) |

Le front envoie `X-CSRF-Token` (valeur de `/auth/me`) et l'en-tête `Origin` sur les requêtes mutantes. Les automates utilisent `Authorization: Bearer lasthop_…`.

## API du lot (b)

| Route | Rôle | Description |
|---|---|---|
| `GET/POST/DELETE /api/v1/sites` | topologie / super admin | Sites |
| `GET/POST/PUT/DELETE /api/v1/credentials` | admin | Profils SNMP (v3 authPriv par défaut ; secrets chiffrés, jamais renvoyés) |
| `GET/POST/PUT/DELETE /api/v1/devices` | super admin | Équipements |
| `POST /api/v1/devices/{id}/test` | admin | Test de connectivité SNMP (job asynchrone) |
| `POST /api/v1/discovery`, `POST /api/v1/discovery/{job}/adopt` | admin | Découverte par plage CIDR puis adoption |
| `GET /api/v1/jobs/{id}` | propriétaire / admin | Statut et résultat d'un job |

Préalable obligatoire : `PUT /api/v1/settings/snmp_allowed_cidrs` (aucune cible SNMP n'est autorisée par défaut).
`snmp_v2c_enabled` est `false` par défaut. Configuration des équipements : [docs/SWITCH_SNMPV3.md](docs/SWITCH_SNMPV3.md).

Rotation de la clé maître : ajouter une clé au trousseau (`secrets/master_keys.json`), la déclarer `active`, puis
`docker compose run --rm api python -m app.cli reencrypt`.

## API du lot (c) — topologie L2

| Route | Rôle | Description |
|---|---|---|
| `POST /api/v1/devices/{id}/topology` | admin | Collecte immédiate (job) : interfaces, LLDP/CDP, trunks, MAC par port |
| `GET /api/v1/devices/{id}/interfaces` | super admin | Vue par port : rôle effectif/détecté/surchargé, raison, nb de MAC, voisins |
| `PUT /api/v1/interfaces/{id}/role` | admin | Surcharge manuelle `access` / `uplink` (`null` = retour automatique), auditée |
| `GET /api/v1/topology/graph?site_id=&include_unmanaged=` | topologie (tous les rôles) | Nœuds + arêtes dédupliquées (format prêt pour Cytoscape au lot f) |

La collecte est aussi **planifiée** : Celery beat lance toutes les 60 s un balayage qui crée un job pour chaque équipement dont la dernière collecte
dépasse `topology_interval_s` (3600 s par défaut). Paramètres : `uplink_mac_threshold` (20), `trunk_min_tagged_vlans` (2), `topology_interval_s`.

Détection du rôle d'un port (premier critère vrai, la surcharge manuelle l'emporte toujours) :
1. voisin LLDP/CDP qui est un équipement réseau (inventaire ou capacités bridge/routeur ; téléphones et bornes Wi-Fi exclus) → `uplink` ;
2. membre tagué de ≥ `trunk_min_tagged_vlans` VLAN (Q-BRIDGE ; CISCO-VTP pour Cisco) → `uplink` ;
3. plus de `uplink_mac_threshold` adresses MAC apprises → `uplink` ;
4. sinon `access`.

## API du lot (d) — IP/MAC Learning

| Route | Rôle | Description |
|---|---|---|
| `POST /api/v1/devices/{id}/learn` | admin | Collecte immédiate ARP (équipement L3) + FDB (équipement L2) |
| `GET /api/v1/endpoints` | recherche | Filtres : `mac` (tous formats, partielle), `ip` (adresse ou CIDR), `vlan`, `device_id`, `hostname`, `active`, pagination |
| `GET /api/v1/endpoints/{id}/history` | recherche | Historique : `appeared`, `moved`, `ip_changed`, `vlan_changed`, `disappeared` |
| `POST /api/v1/oui/update` | admin | Mise à jour de la base OUI IEEE (job) |

Un endpoint est un couple **(MAC, IP)** localisé sur **(équipement, port, VLAN)**. La jointure ARP + FDB **exclut les ports uplink** ; une MAC sans ARP
est conservée avec `ip = null`. Planification : chaque équipement est collecté selon **son** `poll_interval_s` (900 s par défaut) ;
`snmp_context` (champ de l'équipement) fixe le contexte SNMPv3 de base. Sur **Cisco**, la FDB est lue **par VLAN** (liste VTP puis contexte `vlan-X` en v3,
`community@X` en v2c). Tâches périodiques (Celery beat) : balayage de collecte (60 s), DNS inverse (5 min), purge de rétention (03:15), mise à jour OUI (lundi 04:00).
Import OUI hors ligne : `docker compose run --rm api python -m app.cli oui-import /chemin/oui.csv`.

## API du lot (e) — Real-Time Location

| Route | Rôle | Description |
|---|---|---|
| `POST /api/v1/realtime` | opérateur | `{"query": "10.0.0.5" \| "aabb.ccdd.eeff" \| …, "site_id": …}` → `202 {job_id, events_url}` |
| `GET /api/v1/realtime/{job}/events` | opérateur (auteur ou admin) | Flux **SSE** : `started`, `arp_resolving`, `arp_resolved`, `fdb_querying`, `device_queried`, `hop`, `located` \| `failed`, `done` |
| `GET /api/v1/realtime/{job}` | opérateur (auteur ou admin) | Statut et résultat final |

Fonctionnement : IP → ARP **en direct** des passerelles gérées (L3) → MAC → FDB **en direct** de tous les switchs (ou d'un site) : `GET` ciblé
`dot1qTpFdbPort.<vlan>.<mac>` quand le VLAN est connu (apprentissage), `GET` ciblé `dot1dTpFdbPort.<mac>`, sinon parcours avec arrêt à la correspondance ; sur Cisco,
un contexte par VLAN. Le résultat donne le switch d'accès, le port, le VLAN, la **chaîne d'uplinks** du cœur vers l'accès, le fabricant, le nom d'hôte, première/dernière vue et l'historique.
Échecs explicites : `GATEWAY_NOT_MANAGED`, `IP_NOT_IN_ARP`, `MAC_AGED_OUT`, `DEVICE_UNREACHABLE`, `SNMP_AUTH_FAILURE`, `SNMP_ERROR`, `ACCESS_NOT_MANAGED`, `TIMEOUT` (délai global `realtime_timeout_s`, 30 s).
Garde-fous : 6 recherches/min et 2 simultanées par utilisateur, file Celery dédiée `realtime` (service `worker-rt`), chaque recherche et chaque résultat sont **audités**.
Le flux SSE reprend avec l'en-tête `Last-Event-ID` ; il est coupé si la session est fermée ou le token révoqué. Côté navigateur : `new EventSource('/api/v1/realtime/<job>/events')` (cookie de session, même origine).

## Interface web (lot f)

Console d'administration en **Vue 3** (JavaScript) + Vite, **TanStack Table v9**, **Cytoscape.js**, Vue Router. Présentation inspirée des consoles de gestion de switchs :
barre latérale sombre à icônes, bandeau bleu (fil d'Ariane, compteurs, onglets), tableaux épurés avec **compteurs de ports vert/orange**, **pastilles de pilote** (SNMP v3 · Cisco IOS…) et **grille de ports** par équipement.
Icônes SVG intégrées (aucune police ni CDN : compatible avec la CSP stricte).

Pages (affichées selon le rôle ; l'autorisation réelle reste côté serveur) :
Tableau de bord · Recherche globale (+ export CSV) · Localisation en direct (SSE) · Topologie (graphe) · Équipements (liste, fiche avec onglets *Résumé / Ports / Sauvegardes / Journaux*) ·
Sauvegardes (journal lisible) · Profils SNMP · Profils SSH · Découverte CIDR · Paramètres · Audit · Tokens d'API.

```bash
cd front && npm ci --ignore-scripts      # dépendances épinglées (versions exactes + package-lock)
npm test && npm run lint && npm run build
npm run mock &  npm run dev              # développement sans backend : API factice (dev/mock-server.mjs) + Vite sur :5173
npm run csp-preview                      # sert dist/ avec la CSP exacte du Caddyfile (détecte toute violation)
```
Sécurité du front : aucun `v-html`/`innerHTML`/`eval` (règle ESLint + test), aucune donnée dans `localStorage`/`sessionStorage`/cookies lisibles par JS (session = cookie `HttpOnly` géré par l'API),
jeton CSRF en mémoire, CSP stricte (`script-src 'self'`, `style-src 'self'`, sans `unsafe-inline`), rendu texte de toutes les données d'équipements, `npm ci --ignore-scripts`, `npm audit` en CI.
L'export CSV neutralise les formules (`=`, `+`, `-`, `@`) et est audité.

## Sauvegarde des configurations (switchs)

Sauvegarde de la configuration **en cours (running)** et **de démarrage (startup)** des équipements Cisco IOS, HPE Comware et Aruba (ArubaOS-Switch / AOS-CX), à la demande ou **automatiquement** (`backup_interval_s`, 24 h par défaut).

**Pourquoi SSH et pas SNMP** : copier une configuration par SNMP exige des opérations d'écriture (`SET`), interdites par conception dans LastHop. La sauvegarde passe donc par SSH, avec des **commandes d'affichage uniquement** (`show running-config`, `display current-configuration`…) ; un test garantit qu'aucune commande de modification n'est dans le code.

Mise en place (administrateur) :
1. **Profils SSH** : créer un profil (utilisateur + mot de passe *ou* clé privée) ; compte de **lecture seule** recommandé. Le secret est chiffré (AES-GCM) et jamais réaffiché.
2. Fiche de l'équipement → choisir le profil, le port, activer la sauvegarde automatique.
3. **Vérifier l'empreinte SSH** : LastHop lit la clé de l'équipement *sans envoyer d'identifiant* ; vous comparez l'empreinte avec celle de l'équipement et la **ressaisissez** pour l'approuver. Aucune sauvegarde n'est tentée sans empreinte approuvée ; si elle change, la sauvegarde s'arrête avec une alerte.
4. **Sauvegarder maintenant**, ou attendre la planification.

**Journal lisible** (menu *Sauvegardes*) : chaque exécution raconte, en français, ce qui s'est passé — connexion, authentification, récupération de chaque configuration, nouvelle version ou « identique à celle du … », écart running/startup (modifications non enregistrées qui seraient perdues au redémarrage).
En cas d'échec, une phrase explique la cause et un encadré **« Que faire »** propose l'action ; le détail technique est replié. Codes : `SSH_AUTH_FAILED`, `SSH_UNREACHABLE`, `SSH_REFUSED`, `SSH_HOSTKEY_UNKNOWN`, `SSH_HOSTKEY_CHANGED`, `SSH_ALGO_MISMATCH`, `SSH_PRIVILEGE_REQUIRED`, `CLI_PROMPT_TIMEOUT`, `CLI_COMMAND_REJECTED`, `CLI_TIMEOUT`, `CLI_OUTPUT_EMPTY`, `NO_SSH_PROFILE`, `UNSUPPORTED_DRIVER`, `TARGET_NOT_ALLOWED`… Une sauvegarde peut être *incomplète* (running OK, startup en échec).

Stockage : contenu compressé puis **chiffré** (AES-GCM, clé hors base) ; une configuration identique à la précédente n'ajoute pas de version ; rétention `backup_retention_days` (365 j par défaut, la dernière version de chaque type est toujours conservée).
Consultation (**administrateurs uniquement**) : secrets **masqués** par défaut (mots de passe, communities, clés) ; le contenu complet (« brut ») exige une confirmation et est **audité** ; comparaison entre deux versions (secrets masqués).

| Route | Rôle | Description |
|---|---|---|
| `GET/POST/PUT/DELETE /api/v1/ssh-credentials` | admin | Profils SSH |
| `POST /api/v1/devices/{id}/ssh/hostkey` · `…/ssh/trust` | admin | Lire puis approuver l'empreinte (ressaisie obligatoire) |
| `POST /api/v1/devices/{id}/backup` | admin | Lancer une sauvegarde (job) |
| `GET /api/v1/backups/runs`, `/runs/{id}` | admin | Historique et journal lisible |
| `GET /api/v1/devices/{id}/backups`, `/backups/{id}[?raw=true]`, `/backups/diff?a=&b=` | admin | Versions, contenu, comparaison |

## Rôles

| Rôle | Permissions |
|---|---|
| viewer | **recherche IP/MAC** et **topologie réseau** — rien d'autre |
| operator | + localisation en direct (temps réel) et export CSV |
| admin (« super admin ») | seul à gérer : **profils SNMP/SSH**, équipements et découverte, **sauvegardes de configuration**, **paramètres**, **journal d'audit** et **tokens d'API** |

Les tokens d'API ne portent jamais ces droits d'administration (portées `read`, `search`, `topology`, `realtime`, `export` seulement) et leur gestion
est réservée au super admin. Le rôle technique reste `admin` (groupe IdP `lasthop-admins`) ; l'interface l'affiche « Super admin ».

Le rôle vient des groupes IdP (`LASTHOP_OIDC_*_GROUPS`). Aucun groupe reconnu → accès refusé.

## Architecture

Voir [PROPOSITION.md](PROPOSITION.md) (schéma réseau Docker, choix) et [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
Durcissement avant production : [docs/HARDENING_CHECKLIST.md](docs/HARDENING_CHECKLIST.md).

## Développement avec Keycloak

`docker-compose.dev.yml` ajoute un Keycloak local avec un realm importé (`keycloak/lasthop-realm.json`). Cette configuration n'a **pas** été validée de bout en bout.
Les tests automatiques utilisent à la place un IdP simulé (signature RSA réelle).

## Sauvegarde et mise à jour

Voir la checklist. En bref : `pg_dump` chiffré + copie séparée de `secrets/master_keys.json` ; mise à jour = reconstruire les images puis `docker compose up -d` (le service `migrate` applique Alembic).
