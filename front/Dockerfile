# syntax=docker/dockerfile:1.7
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
# ignore-scripts (via .npmrc) : aucun script d'installation de dépendance n'est exécuté
RUN npm ci --ignore-scripts
COPY index.html vite.config.js ./
COPY public ./public
COPY src ./src
RUN npm run build

# Alpine 3.24 + paquet nginx de la distribution : les correctifs de sécurité sont appliqués à la construction (apk upgrade)
# et l'image n'embarque rien d'autre que nginx et les fichiers statiques.
FROM alpine:3.24
# Pas d'épinglage de version apk (DL3018) : on veut précisément la dernière version corrigée à chaque construction ;
# la reproductibilité est assurée par l'épinglage de l'image de base et le scan Trivy (scripts/security-check.sh).
# hadolint ignore=DL3018
RUN apk upgrade --no-cache && apk add --no-cache nginx
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
# La commande est volontairement en forme shell (le « || exit 1 » normalise le code de sortie)
# hadolint ignore=DL3025
HEALTHCHECK --interval=15s --timeout=3s CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
CMD ["nginx", "-e", "/dev/stderr", "-g", "daemon off;"]
