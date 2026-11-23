#!/usr/bin/env bash
# Génère les secrets Docker locaux. N'écrase jamais un fichier existant.
set -euo pipefail
umask 077
d="$(cd "$(dirname "$0")/.." && pwd)/secrets"
mkdir -p "$d"
rnd() { openssl rand -base64 36 | tr -d '\n=+/' | cut -c1-40; }
mk() { [ -e "$d/$1" ] || { printf '%s' "$2" > "$d/$1"; echo "créé : secrets/$1"; }; }

mk postgres_superuser_password "$(rnd)"
mk db_owner_password "$(rnd)"
mk db_app_password "$(rnd)"
mk redis_password "$(rnd)"
[ -e "$d/oidc_client_secret" ] || { : > "$d/oidc_client_secret"; echo "à renseigner : secrets/oidc_client_secret"; }
if [ ! -e "$d/master_keys.json" ]; then
  k="$(openssl rand -base64 32 | tr -d '\n')"
  printf '{"active":"k1","keys":{"k1":"%s"}}' "$k" > "$d/master_keys.json"
  echo "créé : secrets/master_keys.json (clé AES-256 active k1)"
fi
# ACL Redis : utilisateur 'default' désactivé, un seul compte applicatif aux commandes restreintes.
if [ ! -e "$d/redis_users.acl" ]; then
  printf 'user default off\nuser lasthop on >%s ~* &* +@all -@admin -@dangerous +client|setname +client|id +client|setinfo +info\n' \
    "$(cat "$d/redis_password")" > "$d/redis_users.acl"
  echo "créé : secrets/redis_users.acl"
fi
chmod 0644 "$d"/* 2>/dev/null || true   # lisibles par les utilisateurs non-root des conteneurs ; le dossier reste protégé par le FS hôte
