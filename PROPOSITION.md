# LastHop — Proposition d'architecture (à valider avant tout code)

Statut : **proposition**, aucun code écrit. Date : 2026-11-22.

## 0. Vérification de la bibliothèque SNMP

| Paquet PyPI | Dernière version | Verdict |
|---|---|---|
| `pysnmp` | 7.1.33 (2026-11-16), Python ≥ 3.11.5 | **Retenu.** Projet officiel (repris de lextudio), API asyncio `pysnmp.hlapi.v3arch.asyncio`, SNMPv3 SHA-2 (RFC 7860) et AES. |
| `pysnmp-lextudio` | 6.3.0 (2024-10) | Déprécié → écarté. |
| `pysnmplib` | 6.0.0 | Fork tiers, historique de confusion de noms (risque supply chain) → écarté. |
| `snmpsim` | 1.2.2 (2026-04) | Retenu pour les tests (dépendance de dev uniquement). |

Précautions : version épinglée avec hashes (`pip-compile --generate-hashes`), et un adaptateur
`snmp/client.py` qui est le **seul** module important `pysnmp`. Il n'expose que GET / GETNEXT / GETBULK / walk,
donc aucun SET n'existe dans le code. Un test CI (grep AST) échoue si `set_cmd`/`SetRequest` apparaît.
Plan B documenté si pysnmp venait à stagner : `puresnmp` (2.0.2, actif), derrière la même interface.

## 1. Architecture

```
Internet/LAN ──► [proxy Caddy :443]  TLS ≥ 1.2, HSTS, CSP, rate-limit grossier
                   ├─► [front]  nginx-unprivileged, fichiers statiques Vue (read-only)
                   └─► [api]    FastAPI/uvicorn (BFF OIDC, REST, SSE)
                                   │ réseau "backend" (internal: true)
          ┌────────────────────────┼───────────────────────┐
       [redis]  ACL+mdp        [postgres 16]          [worker] [beat]
   (broker, sessions,          (3 rôles SQL)          Celery JSON-only
    pub/sub temps réel)                                  │ réseau "snmp" (egress UDP/161 + DNS)
                                                       switchs / routeurs
```

Choix structurants et justification sécurité :

1. **Seul `worker` parle SNMP** (réseau `snmp`). `api` n'a pas d'accès UDP vers les équipements :
   une compromission de l'API ne donne pas un pivot réseau. `api` a uniquement `edge` (IdP OIDC sortant) et `backend`.
2. **Real-time = job Celery** (queue dédiée `realtime`, prioritaire) qui publie sa progression sur
   Redis pub/sub ; l'API relaie en **SSE** (choix SSE plutôt que WebSocket : unidirectionnel, cookie de session
   standard, pas de problème d'origine/CSRF propre aux WS, reconnexion native).
3. **API = Backend-for-Frontend OIDC** : Authorization Code + PKCE côté serveur, session serveur dans Redis,
   cookie `__Host-` `Secure; HttpOnly; SameSite=Lax`, **aucun token dans le navigateur** (ni localStorage). CSRF : en-tête
   custom obligatoire + vérification `Origin` sur les méthodes non sûres. Rôles dérivés des groupes IdP à chaque login.
4. **Tokens d'API** (automatisation) : séparés des sessions, `lasthop_<prefix>.<secret 256 bits>`, stockés
   **hachés (SHA-256)**, portée limitée (`read`, `search`, `realtime`, `export`), expiration obligatoire, révocables, affichés une seule fois.
   Jamais de portée `admin`.
5. **Secrets SNMP** : AES-256-GCM, enveloppe `{kid, nonce, ciphertext}`, AAD = `credential_id` (empêche de rejouer un blob
   d'un profil à un autre). Clé maître dans un **Docker secret** (fichier monté en lecture seule, uniquement dans `api` et `worker`),
   rotation via `kid` multiple + commande de re-chiffrement. Vault possible plus tard derrière l'interface `KeyProvider`.
   Déchiffrement uniquement dans le `worker`, l'API ne fait que chiffrer à la création/modification et ne relit jamais.
6. **Audit immuable** : table `audit_log` append-only : rôle SQL applicatif avec `INSERT` seul, trigger qui refuse
   `UPDATE/DELETE/TRUNCATE`, **chaîne de hachage** (`row_hash = SHA-256(prev_hash || contenu)`) et vérificateur
   `lasthop audit verify`. Export optionnel vers syslog/SIEM pour une copie hors BDD.
7. **3 rôles PostgreSQL** : `lasthop_owner` (migrations Alembic, jamais utilisé à l'exécution), `lasthop_app` (DML limité, pas de DDL,
   `INSERT` seul sur audit), `lasthop_readonly` (reporting). TLS Postgres/Redis activé sur le réseau interne (certificat interne généré à l'init).
8. **Conteneurs** : utilisateur non-root, `read_only: true` + tmpfs, `cap_drop: [ALL]`, `no-new-privileges`, images `python:3.12-slim`
   (multi-stage) / `nginx-unprivileged`, healthchecks, limites CPU/mémoire.

### Pipeline de collecte (learning)

1. `beat` planifie par équipement (`poll_interval_s`, défaut 900 s) → tâche `collect_device(device_id)`.
2. Le `driver` de la famille (`generic`, `aruba_os`, `comware`, `cisco_ios`) implémente l'interface commune :
   `identify()`, `get_interfaces()`, `get_lldp/cdp_neighbors()`, `get_fdb()`, `get_arp()`, `lookup_mac(mac)` (temps réel), `lookup_ip(ip)`.
3. Concurrence : `asyncio.Semaphore` global (paramètre) + par équipement ; GETBULK (`max_repetitions` par équipement), timeout/retries configurables.
4. Corrélation (fonction pure, très testable) : FDB sur ports **non-uplink** ⨝ ARP par MAC → endpoints ; diff avec l'état précédent →
   `endpoint_history`. Les ports uplink = lien LLDP/CDP connu ∨ trunk 802.1Q ∨ > N MAC, sauf surcharge manuelle (prioritaire).
5. Toute donnée lue sur un équipement (`sysName`, `ifAlias`, `ifDescr`…) est **non fiable** : bornée en longueur, nettoyée
   (caractères de contrôle), échappée au rendu (pas de `v-html`) — `ifAlias` est une vraie vectrice de XSS stocké.

### Real-time location

IP → normalisation → ARP direct sur les L3 (GET ciblé `ipNetToPhysicalPhysAddress`, repli walk) → MAC → FDB directe
(`dot1qTpFdbPort.<vlan>.<mac>`, repli walk, `contextName vlan-X` pour Cisco) sur tous les switchs/un site → suivi de la chaîne
d'uplinks (via `links`) jusqu'au port d'accès final. Événements SSE : `started`, `arp_resolved`, `device_queried`,
`hop`, `located`, `failed(code)`, avec codes explicites : `GATEWAY_NOT_MANAGED`, `MAC_AGED_OUT`, `SNMP_ERROR`, `DEVICE_UNREACHABLE`, `TIMEOUT`.
Garde-fous : rate-limit par utilisateur (Redis), 1–2 jobs simultanés par utilisateur, plafond global de requêtes SNMP, timeout global, audit de chaque recherche.

## 2. Schéma de BDD (PostgreSQL 16, `inet`/`macaddr`)

```
users(id uuid pk, issuer, sub, email, display_name, role enum[admin,operator,viewer],
      is_active, last_login_at, UNIQUE(issuer,sub))
api_tokens(id, user_id fk, name, prefix UNIQUE, token_hash bytea, scopes text[], expires_at NOT NULL,
           revoked_at, last_used_at, created_at)
audit_log(id bigserial, ts timestamptz, actor_type, actor_id, actor_label, action, target_type, target_id,
          source_ip inet, request_id, details jsonb, prev_hash bytea, row_hash bytea)   -- append-only
app_settings(key pk, value jsonb)   -- snmp_v2c_enabled, uplink_mac_threshold, retention_days, max_concurrency, realtime_timeout…

sites(id, name UNIQUE)
snmp_credentials(id, name UNIQUE, version enum[v2c,v3], v3_username, security_level enum[authPriv,authNoPriv],
                 auth_proto, priv_proto, allow_legacy_algos bool, secret_blob bytea, key_id, created_by, updated_at)
devices(id, name, mgmt_ip inet UNIQUE, site_id fk, role enum[core,distribution,access], driver enum,
        vendor, model, sys_name, sys_descr, sys_object_id, is_l3 bool, is_l2 bool, credential_id fk,
        snmp_port, timeout_ms, retries, max_repetitions, poll_interval_s, enabled,
        last_poll_at, last_poll_status, last_error_code)
discovery_runs(id, cidr cidr, started_by, started_at, finished_at, found int)
interfaces(id, device_id fk, if_index, name, descr, alias, bridge_port, oper_status, is_trunk,
           role_detected enum[access,uplink,unknown], role_override enum[access,uplink] NULL, override_by, mac_count,
           UNIQUE(device_id, if_index))
vlans(device_id, vlan_id, name, PRIMARY KEY(device_id, vlan_id))
links(id, a_interface_id fk, b_interface_id fk NULL, remote_chassis, remote_port, remote_sysname,
      protocol enum[lldp,cdp], first_seen, last_seen)
oui(prefix bytea(3) pk, vendor, updated_at) ; oui_import_runs(...)
endpoints(id, mac macaddr, ip inet NULL, vlan int, device_id fk, interface_id fk, hostname, hostname_checked_at,
          first_seen, last_seen, active bool, UNIQUE NULLS NOT DISTINCT (mac, ip))
endpoint_history(id, endpoint_id, ts, change enum[appeared,moved,ip_changed,vlan_changed,disappeared],
                 old jsonb, new jsonb)   -- partitionné par mois (purge = DROP PARTITION)
collection_runs(id, device_id, kind enum[arp,fdb,lldp,iface], started_at, finished_at, status, error_code, row_count)
realtime_jobs(id uuid, user_id, query_raw, query_norm, status, started_at, finished_at, result jsonb, error_code)
```

Index : GiST/btree sur `endpoints(mac)`, `endpoints(ip)`, `(device_id, interface_id)`, `pg_trgm` pour la recherche partielle (hostname/alias).
Contraintes `CHECK` sur les longueurs, `vlan BETWEEN 1 AND 4094`.
Sémantique retenue : un endpoint = couple (MAC, IP), une MAC sans ARP est stockée avec `ip NULL`.

## 3. Arborescence

```
LastHop/
├─ docker-compose.yml  docker-compose.override.example.yml  .env.example  .gitignore
├─ secrets/README.md                (génération des secrets, jamais commités)
├─ proxy/Caddyfile
├─ backend/
│  ├─ pyproject.toml  requirements.lock (hashes)  Dockerfile  alembic.ini  migrations/
│  └─ app/
│     ├─ main.py  config.py  logging.py            (pydantic-settings, logs JSON avec redaction)
│     ├─ security/ oidc.py session.py rbac.py csrf.py tokens.py crypto.py audit.py headers.py ratelimit.py
│     ├─ db/ models.py session.py
│     ├─ api/ v1/ devices.py credentials.py topology.py endpoints.py realtime.py search.py export.py admin.py tokens.py audit.py
│     ├─ schemas/                                   (Pydantic v2, extra="forbid")
│     ├─ snmp/ client.py oids.py usm.py normalize.py
│     ├─ drivers/ base.py generic.py aruba_os.py comware.py cisco_ios.py registry.py
│     ├─ services/ discovery.py topology.py learning.py correlate.py realtime.py oui.py dns.py retention.py
│     └─ worker/ celery_app.py tasks_collect.py tasks_realtime.py tasks_maintenance.py
├─ backend/tests/ unit/ integration/ snmprec/{aruba,comware,cisco}/ conftest.py
├─ frontend/ (Vue 3 + Vite, JS, TanStack Table, Cytoscape.js) src/{views,components,api,stores}
├─ docs/ THREAT_MODEL.md  HARDENING_CHECKLIST.md  SWITCH_SNMPV3.md  OPERATIONS.md
├─ .github/workflows/ci.yml  renovate.json
└─ README.md
```

## 4. Modèle de menaces — aperçu STRIDE (version complète = `docs/THREAT_MODEL.md` au lot a)

| STRIDE | Menace principale | Parade |
|---|---|---|
| **S**poofing | Vol de session/token ; usurpation d'un équipement SNMP | OIDC+MFA IdP, cookie `__Host-`, tokens hachés+expirants ; SNMPv3 authPriv, ACL source côté switch |
| **T**ampering | Altération de l'audit ou de la topologie ; SQLi | Append-only + chaîne de hachage ; ORM seul ; Pydantic `extra=forbid` ; SNMP lecture seule (aucun SET) |
| **R**epudiation | Un opérateur nie une recherche/un export | Audit de login, realtime, export, CRUD inventaire/identifiants, avec `request_id` et IP |
| **I**nformation disclosure | Fuite de la cartographie ; fuite des communities/clés | RBAC, secrets AES-GCM + clé hors BDD, jamais renvoyés/loggés, réseaux Docker internes, TLS, CSP/HSTS, sauvegardes chiffrées |
| **D**enial of service | Real-time abusif qui charge le réseau ; walks géants | Rate-limit, quotas par utilisateur, sémaphore global SNMP, timeouts, `max_repetitions` borné |
| **E**levation | Évasion de conteneur ; IDOR ; élévation de rôle | Non-root/cap_drop/read-only, contrôle d'accès par endpoint testé, rôle recalculé depuis l'IdP |
| Spécifiques | XSS stocké via `ifAlias`/`sysName` ; injection de formules CSV ; découverte CIDR détournée en scanner ; DNS inverse/OUI = canaux sortants | Échappement + CSP stricte ; préfixe `'` des cellules `=+-@` ; **allowlist de CIDR** configurable pour la découverte ; hôtes sortants fixes, taille/timeout bornés, checksum OUI |

## 5. Découpage en lots (inchangé par rapport à votre demande)

(a) socle + OIDC + RBAC + audit + crypto → (b) inventaire/SNMP/drivers de base → (c) topologie → (d) learning →
(e) real-time → (f) front → (g) tests snmpsim + CI sécurité. Chaque lot livre : code, tests verts, commandes, points de sécurité.

## 6. Points à trancher / risques identifiés

Voir les questions posées dans la conversation. Risques à connaître :

- **SHA-256 en SNMPv3** : beaucoup de ProCurve/Comware anciens ne supportent que SHA-1/AES-128. Le repli est un
  réglage **par profil** (`allow_legacy_algos`), désactivé par défaut, journalisé dans l'audit.
- **snmpsim et SNMPv3** : supporte les utilisateurs v3 et les contextes, mais le comportement des contextes Cisco `vlan-X` sera à valider en test ; prévoir un repli de test en v2c@vlan.
- **Données personnelles (RGPD)** : l'association IP/MAC/port/hostname est une donnée de localisation de personnes ;
  rétention par défaut 90 jours pour l'historique, à confirmer.
- **Ce qu'un outil de ce type ne couvre pas** : MAC/ARP dynamiques expirés, endpoints derrière un hub/AP/téléphone, MAC flapping — documentés comme limites.
