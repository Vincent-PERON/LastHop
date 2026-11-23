#!/usr/bin/env bash
# Contrôles de sécurité identiques à ceux de la CI (.github/workflows/ci.yml), exécutables en local.
# Prérequis : Docker. Les outils tournent dans des conteneurs : rien à installer. Code de sortie ≠ 0 au premier échec.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
D="docker run --rm"

step "Secrets (gitleaks : fichiers + historique git)"
$D -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:v8.30.1 dir /repo -c /repo/.gitleaks.toml --redact --no-banner --exit-code 1
[ -d .git ] && $D -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:v8.30.1 git /repo -c /repo/.gitleaks.toml --redact --no-banner --exit-code 1

step "Semgrep (Python, OWASP Top 10, JavaScript, Dockerfile, secrets)"
$D -v "$PWD:/src" -w /src semgrep/semgrep:1.185.0 semgrep \
  --config p/python --config p/owasp-top-ten --config p/javascript --config p/dockerfile --config p/secrets \
  --metrics=off --error --exclude node_modules --exclude dist \
  backend/app front/src front/index.html backend/Dockerfile front/Dockerfile docker-compose.yml proxy

step "Dockerfile (hadolint)"
for f in backend/Dockerfile front/Dockerfile tests-infra/snmpsim/Dockerfile tests-infra/sshsim/Dockerfile; do
  $D -i hadolint/hadolint:v2.14.0 hadolint - < "$f"
done

step "Trivy — dépendances, secrets et configuration du dépôt"
$D -v "$PWD:/src" -v trivy-cache:/root/.cache aquasec/trivy:0.76.2 fs --scanners vuln,secret,misconfig \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --quiet \
  --skip-dirs /src/front/node_modules --skip-dirs /src/front/dist --skip-dirs /src/secrets --skip-dirs /src/backend/.ruff_cache /src

step "Backend : bandit, pip-audit (production + développement), absence de SET SNMP"
docker compose -f docker-compose.test.yml build -q tests
$D -e HOME=/tmp -v "$PWD/backend:/b:ro" --entrypoint sh lasthop-test-tests -c \
  "cd /srv && bandit -q -r app && pip-audit -r /b/requirements.lock --no-deps --disable-pip && pip-audit -r /b/requirements-dev.lock --no-deps --disable-pip"
! grep -rEn 'set_cmd|SetRequest|setCmd' backend/app

step "Front : npm audit (production + développement)"
(cd front && npm audit --audit-level=moderate)

step "Images : construction puis Trivy (HIGH/CRITICAL corrigeables)"
docker build -q --target runtime -t lasthop-api:ci backend >/dev/null
docker build -q -t lasthop-front:ci front >/dev/null
for i in lasthop-api:ci lasthop-front:ci; do
  $D -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache aquasec/trivy:0.76.2 image \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --quiet "$i"
done

printf '\n\033[1;32mTous les contrôles de sécurité sont passés.\033[0m\n'
