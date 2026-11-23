# syntax=docker/dockerfile:1.7
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
# ignore-scripts (via .npmrc) : aucun script d'installation de dépendance n'est exécuté
RUN npm ci --ignore-scripts
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
