// État de session minimal, conservé en mémoire uniquement (aucun stockage navigateur).
import { reactive } from 'vue'

export const session = reactive({ loaded: false, user: null, csrf: null, permissions: [] })

export function can(perm) {
  return session.permissions.includes(perm)
}

export function setMe(me) {
  session.user = { id: me.user_id, label: me.label, role: me.role }
  session.csrf = me.csrf_token
  session.permissions = me.permissions || []
  session.loaded = true
}

export function clearSession() {
  session.user = null
  session.csrf = null
  session.permissions = []
  session.loaded = true
}

// Redirection vers l'IdP : `next` est toujours un chemin interne (le serveur le revalide aussi).
export function loginUrl(path = '/') {
  const safe = path.startsWith('/') && !path.startsWith('//') ? path : '/'
  return `/api/v1/auth/login?next=${encodeURIComponent(safe)}`
}
