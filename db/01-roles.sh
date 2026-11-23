#!/bin/bash
# Exécuté une seule fois à l'initialisation de PostgreSQL (superuser). Crée les rôles à moindre privilège.
set -euo pipefail
owner_pw="$(cat /run/secrets/db_owner_password)"
app_pw="$(cat /run/secrets/db_app_password)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$owner_pw" -v app_pw="$app_pw" -v dbname="$POSTGRES_DB" <<'SQL'
CREATE ROLE lasthop_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE lasthop_app   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE lasthop_readonly NOLOGIN;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO lasthop_owner, lasthop_app, lasthop_readonly;
ALTER SCHEMA public OWNER TO lasthop_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lasthop_app, lasthop_readonly;
SQL
