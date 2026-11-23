# secrets/

Ce dossier reçoit les Docker secrets (fichiers). **Rien ici n'est commité** (voir `.gitignore`).
Générer les secrets locaux : `./scripts/gen-secrets.sh` (ne remplace jamais un secret existant).
Le secret `oidc_client_secret` est fourni par votre IdP (Keycloak/Entra) : à écrire à la main.
