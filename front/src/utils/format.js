export function dt(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'medium' })
}

// Libellés des rôles IdP ; « admin » est le super admin (seul à gérer profils, sauvegardes, paramètres, audit et tokens)
export const USER_ROLE_LABEL = { admin: 'Super admin', operator: 'Opérateur', viewer: 'Lecteur' }

// Fournisseurs d'identité : libellés et consignes (la sécurité vient du serveur, ceci n'est qu'une aide à la saisie)
export const PRESETS = {
  keycloak: { kind: 'oidc', label: 'Keycloak', issuer: 'https://keycloak.example.org/realms/lasthop', groups: true, hint: "Émetteur = URL du realm. Ajoutez au client un mapper « Group Membership » (nom du claim : groups, chemin complet désactivé)." },
  entra: { kind: 'oidc', label: 'Microsoft Entra ID', issuer: 'https://login.microsoftonline.com/<tenant-id>/v2.0', groups: true, hint: "Émetteur = locataire unique (pas « common »). Configurez le claim « groups » dans l'inscription d'application : les groupes sont des identifiants d'objet (GUID). Au-delà de 200 groupes Entra n'envoie plus la liste : utilisez des groupes d'application ou le rôle par défaut." },
  google: { kind: 'oidc', label: 'Google Workspace', issuer: 'https://accounts.google.com', groups: false, hint: "Google ne fournit pas les groupes : l'accès est limité à votre/vos domaine(s) Workspace (obligatoire) et tous reçoivent le rôle par défaut. Le domaine est contrôlé via le claim « hd »." },
  generic: { kind: 'oidc', label: 'OIDC générique', issuer: 'https://idp.example.org/', groups: true, hint: '' },
  ad: { kind: 'ldap', label: 'Active Directory (LDAP)', filter: '(sAMAccountName={username})', uid: 'objectGUID', display: 'displayName', hint: "Compte de service en lecture seule + base de recherche (ex. DC=corp,DC=local). Les groupes viennent de memberOf (DN complets)." },
  ldap: { kind: 'ldap', label: 'LDAP / OpenLDAP / FreeIPA', filter: '(uid={username})', uid: 'entryUUID', display: 'cn', hint: '' },
}

export const RUN_STATUS = {
  running: ['en cours…', 'warn'],
  success: ['réussie', 'ok'],
  partial: ['incomplète', 'warn'],
  failed: ['échouée', 'bad'],
}

export const ROLE_LABEL = { access: 'accès', uplink: 'uplink', core: 'cœur', distribution: 'distribution', unknown: 'inconnu' }

export const ERROR_LABEL = {
  GATEWAY_NOT_MANAGED: 'Passerelle non gérée',
  IP_NOT_IN_ARP: 'IP absente de la table ARP du routeur',
  MAC_AGED_OUT: 'MAC expirée',
  DEVICE_UNREACHABLE: 'Équipement injoignable',
  SNMP_AUTH_FAILURE: 'Échec d’authentification SNMP',
  SNMP_ERROR: 'Erreur SNMP',
  ACCESS_NOT_MANAGED: 'Switch d’accès non géré',
  NO_SWITCHES: 'Aucun switch dans le périmètre',
  TIMEOUT: 'Délai dépassé',
  INTERNAL_ERROR: 'Erreur interne',
  NO_SSH_PROFILE: 'Aucun profil SSH',
  UNSUPPORTED_DRIVER: 'Modèle non reconnu',
  SSH_HOSTKEY_UNKNOWN: 'Empreinte SSH non validée',
  SSH_HOSTKEY_CHANGED: 'Empreinte SSH modifiée',
  SSH_UNREACHABLE: 'SSH injoignable',
  SSH_REFUSED: 'SSH refusé (port fermé)',
  SSH_AUTH_FAILED: 'Identifiants SSH refusés',
  SSH_ALGO_MISMATCH: 'Algorithmes SSH incompatibles',
  SSH_PRIVILEGE_REQUIRED: 'Privilèges insuffisants',
  CLI_PROMPT_TIMEOUT: 'Invite de commande absente',
  CLI_COMMAND_REJECTED: 'Commande refusée',
  CLI_TIMEOUT: 'Réponse trop lente',
  CLI_OUTPUT_EMPTY: 'Configuration vide',
  BACKUP_TOO_LARGE: 'Configuration trop volumineuse',
  TARGET_NOT_ALLOWED: 'Adresse non autorisée',
}
