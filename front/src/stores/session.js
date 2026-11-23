// État de session minimal, conservé en mémoire uniquement (aucun stockage navigateur).
import { reactive } from 'vue'

export const session = reactive({ loaded: false, user: null, csrf: null, permissions: [], mustChange: false })

export function can(perm) {
  return session.permissions.includes(perm)
}

export function setMe(me) {
  session.user = { id: me.user_id, label: me.label, role: me.role, source: me.auth_source || 'oidc' }
  session.mustChange = Boolean(me.must_change_password)
  session.csrf = me.csrf_token
  session.permissions = me.permissions || []
  session.loaded = true
}

export function clearSession() {
  session.user = null
  session.csrf = null
  session.permissions = []
  session.mustChange = false
  session.loaded = true
}

// Chemin de retour après connexion : uniquement un chemin interne (le serveur revalide aussi `next` pour OIDC).
export function safeNext(path) {
  return typeof path === 'string' && path.startsWith('/') && !path.startsWith('//') && !path.includes('\\') ? path.slice(0, 512) : '/'
}

export function oidcLoginUrl(providerId, next = '/') {
  return `/api/v1/auth/oidc/${encodeURIComponent(providerId)}/login?next=${encodeURIComponent(safeNext(next))}`
}
