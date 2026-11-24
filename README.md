# LastHop

Retrouver, à partir d'une adresse IP ou MAC, le switch d'accès, le port et le VLAN où se trouve un équipement, avec topologie L2 et sauvegarde des configurations.

## Tester l'application complète

Prérequis : Docker (Compose v2).

```bash
./scripts/gen-secrets.sh                 # génère les secrets dans ./secrets (jamais commités)
cp .env.example .env                     # puis mettre LASTHOP_ENV=dev, SITE_ADDRESS=localhost,
                                         # LASTHOP_FRONTEND_ORIGIN=https://localhost:8443, HTTPS_PORT=8443, HTTP_PORT=8080
docker compose up -d --build
cat secrets/local_admin_password         # mot de passe initial du compte « admin »
```

Ouvrez `https://localhost:8443` (certificat local : acceptez l'avertissement), connectez-vous avec `admin` : le changement du mot de passe est imposé.

Tests automatiques : `docker compose -f docker-compose.test.yml run --rm --build tests`.

## Mise en production (certificat SSL)

Prérequis : serveur Linux avec Docker, nom DNS pointant vers lui, ports 80/443 ouverts, accès UDP/161 et TCP/22 vers les équipements.

```bash
git clone https://github.com/Vincent-PERON/LastHop.git && cd LastHop
./scripts/gen-secrets.sh
cp .env.example .env
```

Dans `.env` : `SITE_ADDRESS` (ex. `lasthop.example.org`), `LASTHOP_FRONTEND_ORIGIN` (`https://lasthop.example.org`), `LASTHOP_ENV=prod`.

**Certificat — une des deux options :**

- **Let's Encrypt (automatique)** : rien à faire si le nom DNS est public et les ports 80/443 joignables depuis Internet ; le renouvellement est automatique.
- **Votre certificat** (PKI interne, autorité commerciale) :

  ```bash
  cp fullchain.pem privkey.pem proxy/certs/
  sudo chown root:root proxy/certs/*.pem && sudo chmod 0600 proxy/certs/privkey.pem
  ```

  puis décommenter `TLS_SNIPPET=./proxy/tls-custom.caddy` dans `.env`. Renouvellement : remplacer les fichiers, puis `docker compose exec proxy caddy reload --config /etc/caddy/Caddyfile`.

**Démarrage et vérification :**

```bash
docker compose up -d --build
docker compose ps                        # tous « healthy »
curl -I https://lasthop.example.org      # 200 + Strict-Transport-Security
```

**Première connexion** : `admin` + contenu de `secrets/local_admin_password`, puis nouveau mot de passe (12 caractères minimum). Activez ensuite le TOTP (icône clé → *Mon compte*). Les fournisseurs Keycloak, Entra ID, Google Workspace et LDAP s'ajoutent dans **Authentification** (URL de redirection OIDC : `https://lasthop.example.org/api/v1/auth/oidc/callback`).

**Premiers réglages** : *Paramètres* → `snmp_allowed_cidrs` (aucune cible autorisée par défaut), puis profils SNMP/SSH et équipements ([docs/SWITCH_SNMPV3.md](docs/SWITCH_SNMPV3.md)).

**Exploitation** : mise à jour `git pull && docker compose up -d --build` ; sauvegarder la base (chiffrée) et, séparément, `secrets/master_keys.json` ; mot de passe admin perdu :
`echo -n 'nouveau-mot-de-passe' | docker compose run --rm -T api python -m app.cli local-admin-reset admin`.

Avant la mise en service : [docs/HARDENING_CHECKLIST.md](docs/HARDENING_CHECKLIST.md).
