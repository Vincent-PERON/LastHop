# LastHop

Retrouver, à partir d'une adresse IP ou MAC, le switch d'accès, le port et le VLAN où se trouve un équipement (apprentissage périodique et localisation en temps réel), avec topologie L2 et sauvegarde des configurations des switchs.

- [1. Tester l'application](#1-tester-lapplication)
- [2. Mise en production avec certificat SSL](#2-mise-en-production-avec-certificat-ssl)

---

## 1. Tester l'application

Prérequis : Docker (Compose v2) ; Node.js 24 pour l'interface seule.

### 1.1 Tests automatisés (backend, base et simulateurs réels)

```bash
./scripts/gen-secrets.sh
docker compose -f docker-compose.test.yml run --rm --build tests
```

Lance PostgreSQL 16, Redis, des simulateurs SNMP (Aruba, Comware, Cisco) et SSH, applique les migrations, puis exécute toute la suite avec la couverture (~3 min).
Pour nettoyer ensuite : `docker compose -f docker-compose.test.yml down -v`.

### 1.2 Tests de l'interface

```bash
cd front
npm ci --ignore-scripts
npm test && npm run lint && npm run build
```

### 1.3 Essayer l'interface sans backend

Une API factice (équipements, ports, endpoints, topologie, sauvegardes) permet de parcourir tous les écrans, connecté en super admin de démonstration :

```bash
cd front
npm run mock &        # API factice
npm run dev           # http://127.0.0.1:5173
```

Pour vérifier le rendu avec la politique de sécurité (CSP) exacte de production, sans aucune violation :

```bash
npm run build && npm run csp-preview    # http://localhost:5180
```

### 1.4 Essayer l'application complète avec un Keycloak local

```bash
./scripts/gen-secrets.sh
cp .env.example .env     # puis adapter selon l'en-tête de docker-compose.dev.yml (LASTHOP_ENV=dev, issuer Keycloak local…)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Cette configuration (`docker-compose.dev.yml` + `keycloak/lasthop-realm.json`) **n'a pas été validée de bout en bout** : elle sert de point de départ. Elle ne doit jamais servir en production.

---

## 2. Mise en production avec certificat SSL

Le proxy Caddy est le seul service exposé (ports 80 et 443) ; il impose TLS 1.2 minimum, HSTS et une CSP stricte. Vous avez le choix entre un certificat **Let's Encrypt automatique** ou **votre propre certificat**.

### 2.1 Prérequis

- Un serveur Linux avec Docker (Compose v2), à jour, sans port 5432/6379 exposé.
- Un **nom DNS** pointant vers ce serveur (ex. `lasthop.example.org`).
- Un **fournisseur d'identité OIDC** (Keycloak, Entra ID…) avec **MFA imposée côté IdP** et trois groupes : `lasthop-admins` (super admin), `lasthop-operators`, `lasthop-viewers`.
- Pare-feu : entrant 80/443 ; le service `worker` doit joindre les équipements en UDP/161 (SNMP) et TCP/22 (sauvegardes SSH).

### 2.2 Installation

```bash
git clone https://github.com/Vincent-PERON/LastHop.git && cd LastHop
./scripts/gen-secrets.sh          # génère les secrets dans ./secrets (jamais commités)
cp .env.example .env
```

1. **Client OIDC** : créer côté IdP un client confidentiel (code + PKCE S256) dont l'URL de redirection est **exactement** `https://lasthop.example.org/api/v1/auth/callback`, puis écrire son secret dans `secrets/oidc_client_secret`.
2. **`.env`** : renseigner `SITE_ADDRESS`, `LASTHOP_FRONTEND_ORIGIN`, `LASTHOP_OIDC_ISSUER`, `LASTHOP_OIDC_CLIENT_ID`, `LASTHOP_OIDC_REDIRECT_URI` et les groupes. Laisser `LASTHOP_ENV=prod` (refuse un IdP non HTTPS).
3. **Certificat** : une des deux options ci-dessous.

#### Option A — Let's Encrypt automatique (serveur joignable depuis Internet)

Rien à faire : c'est le comportement par défaut. Caddy obtient et **renouvelle seul** le certificat au premier accès.
Conditions : `SITE_ADDRESS` est un nom DNS public qui pointe vers le serveur, et les ports **80 et 443** sont joignables depuis Internet.

#### Option B — Votre propre certificat (PKI interne, autorité commerciale, réseau sans accès Internet)

1. Placer dans `proxy/certs/` la chaîne complète (certificat serveur + intermédiaires) et la clé privée, sous ces noms exacts :

   ```bash
   cp fullchain.pem privkey.pem proxy/certs/
   sudo chown root:root proxy/certs/*.pem && sudo chmod 0600 proxy/certs/privkey.pem
   ```
   Le certificat doit couvrir le nom de `SITE_ADDRESS` (champ SAN). Ces fichiers sont ignorés par git.
2. Dans `.env`, décommenter :

   ```bash
   TLS_SNIPPET=./proxy/tls-custom.caddy
   ```
   Aucune requête ACME n'est alors émise.
3. **Renouvellement** (manuel) : remplacer les deux fichiers puis recharger le proxy : `docker compose exec proxy caddy reload --config /etc/caddy/Caddyfile`.

### 2.3 Démarrage

```bash
docker compose up -d --build
docker compose ps            # tous les services doivent être « healthy » (le service migrate se termine seul)
```

### 2.4 Vérifications

```bash
curl -I https://lasthop.example.org                    # 200 + Strict-Transport-Security
curl -sI http://lasthop.example.org | head -1          # redirection vers HTTPS
openssl s_client -connect lasthop.example.org:443 -servername lasthop.example.org -tls1_1 </dev/null   # doit être refusé
```

Pour un audit complet de la configuration TLS : `testssl.sh https://lasthop.example.org`.
Se connecter ensuite avec un compte du groupe `lasthop-admins`.

### 2.5 Premiers réglages (en super admin)

1. **Paramètres** → `snmp_allowed_cidrs` : déclarer les réseaux de management des équipements (par défaut, **aucune** cible n'est autorisée). Le SNMPv2c reste désactivé tant que vous ne l'activez pas.
2. **Profils SNMP** : créer un profil SNMPv3 authPriv en lecture seule, puis configurer les équipements : [docs/SWITCH_SNMPV3.md](docs/SWITCH_SNMPV3.md) (exemples non testés sur matériel réel, à valider en laboratoire).
3. **Découverte** (plage CIDR) ou ajout manuel des équipements ; **Profils SSH** pour les sauvegardes de configuration (empreinte SSH à vérifier et approuver).

### 2.6 Exploitation

- **Mise à jour** : `git pull && docker compose up -d --build` (le service `migrate` applique les migrations).
- **Sauvegardes** : `pg_dump` **chiffré** de la base, et copie **séparée** de `secrets/master_keys.json` (sans elle, les identifiants SNMP/SSH chiffrés sont irrécupérables).
- **Journal d'audit** : vérification d'intégrité planifiée avec `docker compose run --rm api python -m app.cli audit-verify` (code de sortie ≠ 0 = chaîne rompue).
- **Rotation de la clé maître** : ajouter une clé au trousseau `secrets/master_keys.json`, la déclarer `active`, puis `docker compose run --rm api python -m app.cli reencrypt`.
- **Avant la mise en service** : parcourir [docs/HARDENING_CHECKLIST.md](docs/HARDENING_CHECKLIST.md) ; analyse des menaces dans [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
