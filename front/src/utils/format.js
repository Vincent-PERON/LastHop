export function dt(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'medium' })
}

// Libellés des rôles IdP ; « admin » est le super admin (seul à gérer profils, sauvegardes, paramètres, audit et tokens)
export const USER_ROLE_LABEL = { admin: 'Super admin', operator: 'Opérateur', viewer: 'Lecteur' }

export const RUN_STATUS = {
  running: ['en cours…', 'warn'],
  success: ['réussie', 'ok'],
  partial: ['incomplète', 'warn'],
  failed: ['échouée', 'bad'],
}

export const ROLE_LABEL = { access: 'accès', uplink: 'uplink', core: 'cœur', distribution: 'distribution', unknown: 'inconnu' }

export const ERROR_LABEL = {
  GATEWAY_NOT_MANAGED: 'Passerelle non gérée',
  IP_NOT_IN_ARP: 'IP absente de l’ARP',
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
