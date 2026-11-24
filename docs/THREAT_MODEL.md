# Modèle de menaces LastHop (STRIDE)

Version : lot (a). Sera complété à chaque lot (SNMP au lot b, collecte au lot d, temps réel au lot e, front au lot f).

## 1. Actifs à protéger

| Actif | Pourquoi | Impact si compromis |
|---|---|---|
| Cartographie réseau (équipements, ports, VLAN, liens, endpoints IP/MAC) | Reconnaissance complète du SI | Confidentialité — haute |
| Identifiants SNMP (communities, clés v3) | Accès lecture à tout le réseau | Confidentialité — critique |
| Clé maître AES-GCM | Déchiffre tous les identifiants | Critique |
| Journal d'audit | Preuve des actions, conformité | Intégrité — haute |
| Sessions / tokens d'API | Usurpation d'un opérateur | Haute |
| Association personne ↔ poste ↔ port | Donnée personnelle (RGPD) | Moyenne/haute |

## 2. Acteurs et frontières de confiance

- **Utilisateur authentifié** (viewer / operator / admin) : navigateur → proxy.
- **Attaquant externe non authentifié** : atteint uniquement le proxy (443/80).
- **Attaquant interne sur le LAN** : peut forger du trafic SNMP/ARP, tenter de joindre les ports Docker de l'hôte.
- **Équipement réseau compromis ou mal configuré** : source de données non fiables (sysName, ifAlias, tables ARP/FDB).
- **Conteneur compromis** (ex. API via une vulnérabilité de dépendance).
- **Administrateur malveillant ou compte admin volé**.

Frontières : Internet/LAN → **proxy** → **api** (réseau `edge`+`backend`) → **postgres/redis** (réseau `backend` interne) ;
**worker** seul relié au réseau `snmp` ; **IdP** externe (OIDC).

## 3. Analyse STRIDE par composant

### Proxy (Caddy)
| | Menace | Parade | Résiduel |
|---|---|---|---|
| S | Faux serveur / interception | TLS 1.2+ (Caddy), HSTS | Certificat à gérer (ACME ou PKI interne) |
| T | Altération des en-têtes (X-Forwarded-For) | Le proxy réécrit XFF ; l'API ne fait confiance qu'au sous-réseau `edge` (`FORWARDED_ALLOW_IPS`) | Si le sous-réseau est mal configuré, l'IP d'audit est falsifiable |
| D | Requêtes volumineuses / lentes | `request_body max_size 1MB`, limite applicative, rate-limit applicatif | Pas de WAF ; ajouter un filtrage amont si exposé hors LAN |
| I | Fuite de version | `-Server`, `server_tokens off` | — |

### API (FastAPI)
| | Menace | Parade | Résiduel |
|---|---|---|---|
| S | Vol de session | Cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, ID aléatoire 256 bits, **haché** dans Redis, expiration inactive 30 min + absolue 8 h | XSS du front = session utilisable (CSP stricte atténue) |
| S | Login CSRF / injection de code OIDC | `state` à usage unique lié au navigateur par cookie, PKCE S256, `nonce` | — |
| S | Falsification d'`id_token` | Signature vérifiée via JWKS, liste blanche RS256/PS256/ES256 (pas de `none`/HS*), `iss`, `aud`, `azp`, `exp`, `nbf`, `nonce` | Confiance dans l'IdP |
| T | CSRF sur requêtes mutantes | En-tête `X-CSRF-Token` lié à la session + contrôle strict de `Origin` ; pas de CSRF possible avec token Bearer | — |
| T | Injection SQL | SQLAlchemy uniquement, requêtes paramétrées, Pydantic `extra=forbid`, aucune concaténation (test de fuzz sur `action`) | — |
| R | Déni d'une action | Audit : connexions (succès/échec), refus d'accès, création/révocation de token, changement de paramètre ; `request_id` + IP | Les lots suivants ajoutent recherches, exports, inventaire, identifiants |
| I | Fuite par messages d'erreur | Erreurs génériques, 422 sans écho de la valeur saisie, 500 avec `request_id` seulement, logs JSON avec masquage | — |
| I | Énumération d'utilisateurs / de tokens | Mêmes réponses 401/404 ; refus par défaut sans groupe IdP mappé | — |
| D | Brute-force de tokens | Rate-limit par IP sur l'authentification Bearer (60/min) et sur login/callback | Rate-limit par IP : contournable derrière NAT (ajouter par utilisateur au lot e) |
| E | Élévation de rôle | RBAC à permissions fines, rôle **recalculé depuis l'IdP à chaque login**, utilisateur relu en base à chaque requête (désactivation immédiate), token plafonné au rôle courant du propriétaire, un token ne peut pas créer de token | Délai = durée de session pour un changement de groupe côté IdP (le rôle est relu au login) |
| E | Open redirect | `next` limité aux chemins internes, validé | — |

### Redis
| | Menace | Parade |
|---|---|---|
| S/E | Accès non authentifié, commandes dangereuses | Réseau `internal`, ACL (utilisateur `default` désactivé, `-@admin -@dangerous`), mot de passe fichier |
| T | Désérialisation (Celery) | JSON uniquement (`accept_content=["json"]`), testé |
| I | Lecture de sessions | Clés = SHA-256 de l'ID de session (un dump Redis ne donne pas de cookie valide) |
| D | Saturation | Limites mémoire du conteneur ; pas de persistance |

### PostgreSQL
| | Menace | Parade |
|---|---|---|
| E | Compromission de l'API → destruction de l'audit/DDL | Rôle `lasthop_app` : DML uniquement, **INSERT/SELECT seul sur `audit_log`**, pas de DDL (testé) ; migrations par `lasthop_owner` dans un conteneur éphémère |
| T | Falsification de l'audit | Triggers `UPDATE/DELETE/TRUNCATE` interdits + **chaîne SHA-256 calculée par la base** ; `audit_verify()` détecte une altération même par le propriétaire (testé) |
| I | Lecture du disque/sauvegardes | Secrets SNMP chiffrés AES-GCM (clé hors base) ; chiffrer les sauvegardes (checklist) |

### Secrets et chiffrement
| Menace | Parade | Résiduel |
|---|---|---|
| Vol de la base | Blob AES-256-GCM, nonce aléatoire, AAD liée à la ligne (copie d'un blob impossible), rotation par `kid` | Clé maître = fichier monté dans `api` et `worker` : une compromission de ces conteneurs l'expose (Vault réduirait ce risque) |
| Secret dans logs/images/dépôt | Masquage dans les logs et l'audit, `.env`/`secrets/` ignorés par git, aucun secret dans les images | Revue des diff avant commit |

### Conteneurs / réseau
Non-root (UID 10001), FS en lecture seule, `cap_drop: ALL`, `no-new-privileges`, healthchecks, limites de ressources,
réseau `backend` interne, `api` **sans accès** au réseau `snmp`.
Résiduel : Postgres exige quelques capacités au premier démarrage ; TLS interne Postgres/Redis non activé par défaut (support présent dans la configuration, PKI interne à fournir).

### Chaîne d'approvisionnement
Dépendances épinglées avec hash (`pip --require-hashes`), puis, en CI (`.github/workflows/ci.yml`, `codeql.yml`) et en local (`scripts/security-check.sh`) :
`pip-audit` (production et développement), `npm audit`, bandit, semgrep (Python, OWASP Top 10, JavaScript, Dockerfile, secrets), CodeQL (hebdomadaire),
gitleaks (fichiers **et historique git**), hadolint, Trivy (dépôt : dépendances/secrets/configuration ; images : HIGH/CRITICAL corrigeables bloquants), revue des
dépendances sur les pull requests, SBOM CycloneDX des images. Actions GitHub **épinglées par SHA**, droits `contents: read` par défaut. Renovate pour les mises à jour.
Images : `apt-get upgrade` (API) et Alpine 3.24 + `apk upgrade` (front, utilisateur non privilégié) pour embarquer les correctifs de l'OS ; premier scan réel : 1 CVE HIGH (API)
et 6 (front, base nginx sur Alpine 3.21 en fin de support) corrigées.
Bibliothèque SNMP : `pysnmp` officiel (activement maintenu).
Limite : les exceptions gitleaks (`.gitleaks.toml`) sont restreintes aux motifs exacts des identifiants jetables des tests ; toute autre fuite reste bloquante.

## 3 bis. Lot (b) — inventaire et SNMP

| Menace | Parade en place (testée) |
|---|---|
| SSRF / scan réseau via création d'équipement, découverte ou test | Liste blanche `snmp_allowed_cidrs` (**vide par défaut = aucune cible**), refus de loopback / link-local (métadonnées cloud) / multicast, plage de découverte ≤ 1024 adresses et incluse dans la liste, **revérifiée par le worker** ; rate-limit 10 jobs/min/utilisateur |
| Écriture SNMP sur le parc | Aucune primitive d'écriture importée ; tests qui échouent si `set_cmd`/`SetRequest` apparaît dans `app/` ; client réduit à `get`/`walk` |
| Vol des identifiants SNMP | AES-256-GCM + AAD par profil (copie d'un blob impossible), secrets jamais renvoyés/loggés/audités, déchiffrement uniquement dans le worker, rotation par `reencrypt` |
| Algorithmes faibles | authPriv uniquement ; MD5/DES absents ; SHA-1 exige `allow_legacy_algos` (contrainte SQL + validation) ; communities triviales refusées ; v2c désactivé globalement par défaut et revérifié par le worker |
| Données d'équipement hostiles (sysDescr, ifAlias…) | Nettoyage (contrôles retirés, longueurs bornées) à l'ingestion ; échappement au rendu (front, lot f) |
| DoS par walk géant ou découverte | `max_rows`, `max_repetitions` borné, sémaphore de concurrence (paramètre), timeouts courts en découverte |
| Fuite d'inventaire à un viewer/operator | Seules la recherche, la topologie (graphe, sites) et — pour l'opérateur — le temps réel et l'export sont accessibles ; liste/fiche des équipements, profils, sauvegardes, paramètres, audit et tokens sont réservés au super admin (`admin`, vérifié côté serveur, refus audités) ; les jobs ne sont lisibles que par leur auteur ou un admin |

Résiduel lot (b) : les profils (nom, algorithmes) sont visibles des admins uniquement mais la clé maître reste lisible par le conteneur `worker`
(compromission du worker = accès aux secrets SNMP — d'où l'ACL source sur les équipements et un compte lecture seule).
Les exemples de configuration des switchs ne sont pas validés sur matériel réel.

## 3 ter. Lot (c) — topologie

| Menace | Parade en place (testée) |
|---|---|
| Voisin LLDP/CDP forgé (usurpation d'un switch, nom/MAC falsifiés) | La corrélation exige un candidat **unique** (MAC de châssis, puis IP, puis nom) : en cas d'ambiguïté aucun lien n'est créé ; les liens ne modifient jamais un équipement ni ses identifiants, seulement l'affichage et le rôle des ports |
| Classement erroné d'un port en `uplink` (qui masquerait des endpoints au lot d) | Téléphones/bornes exclus des voisins « réseau », seuil de MAC et nombre de VLAN tagués paramétrables, **surcharge manuelle prioritaire et auditée** |
| Champs hostiles (`ifAlias`, noms de voisins) | Nettoyés/bornés à la collecte, stockés bruts sans HTML ; échappement au rendu (lot f) |
| Jobs concurrents corrompant la corrélation | Verrou consultatif PostgreSQL pendant l'écriture ; la collecte SNMP reste parallèle |
| Balayage planifié saturant le réseau | 200 jobs max par balayage, pas de doublon pour un équipement déjà en file, concurrence limitée par le worker |

Résiduel : sans LLDP/CDP, la détection repose sur trunk/MAC (heuristique) ; sur Cisco, les MAC par port ne sont lus que dans le contexte par défaut
tant que le lot (d) n'a pas ajouté la lecture par VLAN ; la vue topologique ne prouve pas la réalité physique (un voisin LLDP est une déclaration de l'équipement distant).

## 3 quater. Lot (d) — learning IP/MAC

| Menace | Parade en place (testée) |
|---|---|
| Une collecte incomplète fait « disparaître » des postes (ou en crée de faux) | Le job échoue **avant** toute écriture si SNMP échoue : aucun endpoint n'est modifié ; la correspondance ARP/FDB n'est écrite qu'en une transaction ; statut de la dernière collecte exposé |
| Usurpation / flapping de MAC (un poste imite un autre) | Observation la plus récente puis port le moins chargé ; chaque déplacement est tracé dans `endpoint_history` (visible, jamais écrasé) |
| Endpoints masqués par un port faussement classé uplink | Surcharge manuelle prioritaire (lot c) ; les MAC d'un port forcé en uplink deviennent inactives à la collecte suivante |
| Données hostiles (nom DNS, fabricant OUI) | Nom DNS validé par expression stricte (RFC 1123) et borné ; fabricant nettoyé/borné, stocké brut et échappé au rendu (lot f) |
| Injection par les filtres de recherche (MAC/IP/hôte) | MAC = hexadécimal uniquement ; IP/CIDR parsés par `ipaddress` ; recherche d'hôte par `strpos` (aucun joker `LIKE`) ; paramètres bornés (limit ≤ 200) |
| Téléchargement OUI détourné | HTTPS uniquement, hôte en liste blanche (`standards-oui.ieee.org`), pas de redirection, 30 Mo max ; import hors ligne possible |
| Fuite du réseau interne par le DNS inverse | Résolution via le résolveur du système, uniquement pour les IP vues en ARP, 20 requêtes parallèles, timeout 2 s, re-vérification toutes les 24 h |
| Données personnelles (poste ↔ IP ↔ port) conservées trop longtemps | Purge quotidienne (`retention_days`, 90 par défaut) des endpoints et historiques ; l'audit n'est jamais purgé |
| DoS par les tables SNMP volumineuses | `max_rows` 200 000 par table, GETBULK borné, VLAN Cisco interrogés avec concurrence ≤ 8, purge par lots de 10 000 |

Résiduel : l'historique reflète ce que les équipements déclarent (une MAC peut être usurpée) ; entre deux collectes (15 min par défaut) un déplacement n'est pas vu
(le temps réel du lot e comble ce besoin) ; pas de partitionnement de `endpoint_history` (purge par DELETE en lots) — à envisager au-delà de quelques millions de lignes ;
le DNS inverse sort du `worker` vers le résolveur de l'hôte (à restreindre par pare-feu) ; la mise à jour OUI exige une sortie HTTPS du `worker` vers l'IEEE (ou l'import hors ligne).

## 3 quinquies. Lot (e) — localisation en temps réel

| Menace | Parade en place (testée) |
|---|---|
| Recherche utilisée pour charger/scanner le réseau | Réservée aux rôles opérateur/admin (ou token `realtime`) ; **6/min et 2 simultanées par utilisateur** ; délai global ; sémaphore SNMP ; GET ciblés (pas de parcours complet quand le VLAN est connu) ; interrogation limitée aux équipements **déjà inventoriés** et à la liste blanche de cibles |
| Espionnage des recherches d'un autre utilisateur via le flux | Job lisible seulement par son auteur ou un admin (404 sinon) ; flux revalidé toutes les 5 s (session fermée, utilisateur désactivé, token révoqué ⇒ coupure) |
| Injection via `Last-Event-ID` ou la saisie | Identifiant de reprise validé par expression stricte ; saisie = adresse IP (`ipaddress`) ou MAC hexadécimale uniquement ; JSON borné |
| Fausse conclusion (MAC « expirée » alors qu'un switch est muet) | Un équipement en échec empêche de conclure « MAC expirée » : code explicite (`DEVICE_UNREACHABLE`…) listant les équipements concernés |
| Ports multiples / MAC périmée | Plusieurs ports d'accès ⇒ avertissement `MAC_MULTIPLE_LOCATIONS` + alternatives ; port le moins chargé retenu |
| Absence de traçabilité | `realtime.search` (qui, quoi, quand, IP source) dans la transaction de création du job, puis `realtime.result` ; l'audit reste append-only |
| Fuite via le flux (événements en clair, cache) | Seuls noms d'équipements/ports/VLAN circulent (aucun secret) ; Redis Stream à durée de vie 15 min ; `Cache-Control: no-cache` ; proxy sans mise en tampon |

Résiduel : la précision dépend de la fraîcheur des tables des équipements (FDB vieillie en 5 min par défaut) ; la liaison port→voisin de la chaîne dépend du dernier passage de la topologie ;
le flux SSE d'une session déjà ouverte survit jusqu'à 5 s après une révocation ; limite par utilisateur (pas de quota global réseau) ; le résultat contient des données personnelles (hôte, IP, poste)
conservées en base jusqu'à la purge des jobs (30 jours).

## 3 sexies. Lot (f) — interface web

| Menace | Parade en place (testée) |
|---|---|
| XSS stocké via données d'équipements (`ifAlias`, `sysName`, fabricant OUI, nom DNS) | Tout est rendu en **texte** (interpolation Vue) ; règle ESLint `vue/no-v-html` + test qui interdit `v-html`/`innerHTML`/`eval` ; tests avec charges hostiles ; CSP `script-src 'self'` |
| Vol de session / jeton par script | Session en cookie `HttpOnly` (jamais lisible en JS) ; test interdisant `localStorage`, `sessionStorage`, `document.cookie` ; secret de token d'API affiché une fois, en mémoire seulement |
| CSRF | En-tête `X-CSRF-Token` (valeur de `/auth/me`) sur toute écriture + contrôle `Origin` côté serveur |
| Violations de CSP / relâchement involontaire | Vérifié dans un navigateur avec la **CSP exacte du Caddyfile** : Cytoscape injectait une balise `<style>` ; corrigé par une règle CSS équivalente **sans** `unsafe-inline` ; aucun style/script en ligne (test) |
| Injection de formules via l'export CSV | Cellules `=`, `+`, `-`, `@`, tab, CR préfixées d'une apostrophe ; export réservé aux rôles `export`, audité (filtres + nombre de lignes), plafonné à 50 000 lignes |
| Chaîne d'approvisionnement npm | Versions exactes + `package-lock.json`, `npm ci --ignore-scripts`, `overrides` pour les correctifs minimatch/glob, `npm audit` en CI (0 vulnérabilité) ; seulement 4 dépendances d'exécution (Vue, Vue Router, TanStack Table, Cytoscape) |
| Redirection ouverte à la connexion | `next` limité à un chemin interne (client et serveur) |
| Confusion d'autorité (menus cachés ≠ droits) | L'interface masque selon le rôle par confort ; **toute** action est revérifiée par l'API (RBAC testé aux lots a à e) |

Résiduel : l'image du front est servie derrière Caddy (en-têtes de sécurité posés par le proxy) ; sans le proxy, nginx seul n'ajoute pas la CSP ; le style de Cytoscape (canvas) n'est pas accessible aux lecteurs d'écran (le tableau des équipements et des ports en est l'alternative textuelle) ;
l'interface n'a pas été auditée en accessibilité complète ni testée sur tous les navigateurs.

## 3 septies. Sauvegarde des configurations (SSH)

Nouvelle surface sensible : un identifiant SSH d'accès aux équipements et des configurations qui contiennent des secrets (hachés ou chiffrés) et la cartographie complète.

| Menace | Parade en place (testée) |
|---|---|
| Modification involontaire d'un équipement | Aucune écriture SNMP ; côté SSH, **commandes d'affichage uniquement** (profils fixes, test qui interdit `write`, `copy`, `configure`, `reload`, `save`…) ; pas de saisie utilisateur dans les commandes |
| Usurpation / interception (MITM) d'un équipement | **Épinglage de la clé d'hôte** : lecture sans authentification, approbation humaine avec **ressaisie** de l'empreinte, changement ⇒ arrêt avant tout envoi d'identifiant (`SSH_HOSTKEY_CHANGED`) ; l'API ne touche jamais le réseau (le worker lit la clé) |
| Vol du mot de passe / de la clé SSH | AES-GCM + AAD par profil, clé hors base, jamais renvoyé, journalisé ni audité (testé), clé privée validée à la création, secret effacé du formulaire |
| Fuite des configurations | Chiffrées au repos (compression + AES-GCM, AAD par version) ; lecture **réservée aux administrateurs** ; secrets **masqués** par défaut ; accès brut **audité** (`backup.view_raw`) ; comparaison masquée et auditée |
| SSRF / scan de ports via l'outil | Cible limitée à la liste blanche de réseaux (`snmp_allowed_cidrs`) et revérifiée par le worker ; ports configurables par équipement seulement par un admin |
| Algorithmes SSH faibles | Défauts modernes d'asyncssh ; algorithmes hérités uniquement via un réglage **par équipement**, tracé dans l'audit |
| Sauvegarde corrompue ou vide prise pour valide | Sortie validée (taille minimale, marqueurs d'erreur CLI, pagination retirée, 5 Mo max) ; rien d'incomplet n'est enregistré |
| Équipement qui bloque la collecte (invite absente, réponse lente) | Délais stricts (connexion 10 s, invite 15 s, commande 90 s) ; échec expliqué, jamais d'attente infinie |
| Journal trompeur ou illisible | Messages rédigés pour des humains avec « Que faire » ; détail technique séparé, nettoyé de tout secret |

Résiduel : le compte SSH doit pouvoir afficher la configuration complète (privilège élevé sur certains équipements) : utiliser un compte dédié, restreint par ACL à l'hôte LastHop et journalisé côté équipement ;
le masquage des secrets est un *au mieux* (expressions régulières) : le contenu brut chiffré reste la référence ; la clé maître est lisible par `api` et `worker` (comme pour SNMP) ;
le parcours CLI (invite, pagination, commandes) a été validé contre des équipements simulés, **pas sur du matériel réel** : chaque famille/firmware peut avoir des particularités.

## 3 octies. Authentification : compte local, OIDC multi-fournisseurs, LDAP

| Menace | Mesure | Résiduel |
|---|---|---|
| Force brute / bourrage d'identifiants (compte local) | argon2id (64 Mio), limitation par IP (20/min), **verrouillage progressif** par compte (5 échecs → 15 min, x2 jusqu'à 1 h), réponse identique que le compte existe ou non (hash factice : temps constant) | Un attaquant peut verrouiller le compte admin (déni de service) : `local-admin-reset` en secours ; **TOTP facultatif** (voir ci-dessous) : tant qu'il n'est pas activé, mot de passe seul — à compenser par un accès réseau restreint |
| Mot de passe initial connu | Généré aléatoirement (Docker secret), **changement imposé** : aucune autre route accessible avant ; sessions antérieures invalidées à chaque changement | Le fichier initial reste sur l'hôte tant qu'il n'est pas supprimé |
| Élévation via un IdP/annuaire compromis ou mal configuré | Un compte fédéré **n'est jamais super admin** : les groupes n'attribuent que operator/viewer (validation + `CHECK` SQL) ; rôle recalculé à chaque connexion ; refus par défaut sans correspondance | Un IdP compromis peut obtenir operator (lecture de la topologie/localisation) |
| Connexion Google ouverte à tout compte Google | Domaine Workspace obligatoire (claim `hd`, pas seulement l'e-mail), e-mail vérifié booléen exigé | |
| Bind LDAP anonyme (mot de passe vide) | Mot de passe vide refusé avant tout appel ; nom d'utilisateur à jeu de caractères restreint ; valeurs échappées dans les filtres (testé : joker, injection) | |
| Interception LDAP | LDAPS/StartTLS, TLS ≥ 1.2, certificat **et nom** vérifiés (testé contre un annuaire réel : autorité inconnue et nom erroné refusés) ; le mode non chiffré exige une reconnaissance explicite, signalé et audité | Mode non chiffré = mots de passe en clair sur le réseau (choix du propriétaire, laboratoire) |
| Secrets de fournisseurs (client_secret, compte de service) | AES-GCM, clé hors base, AAD liée à la ligne ; jamais renvoyés (`has_secret`), jamais dans l'audit | |
| SSRF via la configuration d'un fournisseur | Réservé au super admin ; hôtes refusés : boucle locale, link-local (métadonnées cloud), multicast ; https obligatoire en production pour OIDC ; messages d'erreur génériques | Les résolutions DNS vers des adresses internes ne sont pas filtrées |
| Saisies hostiles dans l'identifiant | Validation (`[A-Za-z0-9._@-]`) avant la base ; libellés d'audit assainis (un NUL faisait échouer l'insertion : bug trouvé par les tests) | |
| Épuisement de l'annuaire (verrouillage AD) | 10 échecs / 15 min par (fournisseur, identifiant) puis 429 | |
| Vol du mot de passe local | **TOTP** facultatif (RFC 6238, SHA-1, 6 chiffres, ±1 pas) : secret 160 bits **chiffré AES-GCM** (AAD liée au compte), jamais renvoyé après la configuration ; connexion en 2 étapes **sans session** après le mot de passe (défi aléatoire à usage limité : 5 min, 5 essais) ; **anti-rejeu** (pas déjà accepté refusé, UPDATE conditionnel : testé en concurrence) ; échecs comptés dans le verrouillage ; activation/désactivation exigent mot de passe (+ code) | Codes de secours : 10 codes à usage unique stockés hachés, affichés une seule fois ; appareil + codes perdus = `local-admin-disable-totp` (accès au serveur) |
| QR code / secret exposés | Le QR est généré côté serveur (SVG en `data:`, autorisé par la CSP `img-src`), uniquement dans la réponse à la configuration, après réauthentification | Visible à l'écran pendant la configuration |
Dépendances : `segno` (QR code, pure Python, sans dépendance transitive) ; `ldap3` (pure Python, sans vulnérabilité connue) n'est plus publié depuis 2021 : exposition limitée (appels sortants vers des annuaires configurés par le super admin, entrées échappées) ; à surveiller.

## 3 nonies. Diagnostic SNMP et parcours hors ligne

| Menace | Mesure |
|---|---|
| Le diagnostic comme outil de scan | Job réservé au super admin, mêmes garde-fous de cible que les autres jobs (réseaux autorisés, v2c désactivé par défaut), lecture seule (GET/walk, aucun SET), audité (`device.diagnose`) |
| Fuite via le résultat du diagnostic | Seulement des compteurs et 3 exemples nettoyés par ligne (`as_text`), jamais d'identifiant SNMP ; rendu en texte côté interface (testé avec du HTML hostile) |
| Données client dans les parcours de test | Outil d'anonymisation cohérent (MAC avec conservation de l'OUI, IP, noms, descriptions, séries ; sel aléatoire, irréversible) **mais relecture humaine obligatoire** (texte libre) ; les parcours restent dans le dépôt : ne jamais publier un parcours non relu |
| Fichier de parcours hostile (CLI) | Lecture bornée, analyse tolérante sans exécution ; la commande n'ouvre aucune connexion réseau |

## 4. Menaces à traiter dans les lots suivants (déjà identifiées)

- **b/d** XSS stocké via `ifAlias`/`sysName`/`ifDescr` → nettoyage à l'ingestion + échappement au rendu + CSP.
- **d** Empoisonnement de la FDB/ARP (usurpation de MAC) → marquer les endpoints « flapping », ne jamais faire confiance à une seule observation pour une action.
- **e** DoS du réseau par recherches temps réel → quotas par utilisateur, sémaphore global, timeout, audit de chaque recherche.
- **e** SSE : authentification par cookie de session + contrôle d'origine, fermeture à l'expiration de session.
- **f** Injection de formules CSV à l'export, pas de `v-html`, CSP sans `unsafe-inline`.
- **RGPD** Rétention 90 jours par défaut ; l'audit des recherches contient des IP/MAC : durée de conservation à définir avec le DPO.

## 5. Risques résiduels acceptés au lot (a)

1. Le rôle d'un utilisateur fédéré est recalculé à sa connexion seulement (la désactivation `is_active` est, elle, immédiate).
2. Rate-limit par IP uniquement.
3. TLS interne Postgres/Redis non déployé par défaut (réseau interne isolé).
4. Un propriétaire de base (`lasthop_owner`) qui désactive les triggers peut altérer l'audit — la rupture est détectable par `audit_verify()` ; la parade complète est l'export syslog/SIEM (à brancher en production).
