# secrets/

Ce dossier reçoit les Docker secrets (fichiers). **Rien ici n'est commité** (voir `.gitignore`).
Générer les secrets locaux : `./scripts/gen-secrets.sh` (ne remplace jamais un secret existant).
`local_admin_password` est le mot de passe initial du super admin local (utilisé une seule fois, changement imposé à la première connexion). Les secrets des fournisseurs d'identité (client_secret OIDC, mot de passe LDAP de service) se saisissent dans l'interface et sont chiffrés en base.
