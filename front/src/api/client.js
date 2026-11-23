// Client HTTP : session par cookie HttpOnly (aucun jeton n'est stocké côté navigateur), en-tête CSRF sur les écritures.
import { session } from '../stores/session.js'

export class ApiError extends Error {
  constructor(status, message, detail) {
    super(message)
    this.status = status
    this.detail = detail
  }
}

const MESSAGES = {
  401: 'Session expirée : reconnexion nécessaire.',
  403: 'Accès refusé.',
  404: 'Introuvable.',
  409: 'Conflit : cette ressource existe déjà ou est utilisée.',
  413: 'Requête trop volumineuse.',
  422: 'Saisie invalide.',
  429: 'Trop de requêtes : réessayez dans un instant.',
  503: 'Service momentanément indisponible.',
}

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

export function qs(params) {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

export async function api(method, path, { body, params, quiet401 = false } = {}) {
  const headers = { Accept: 'application/json' }
  const init = { method, headers, credentials: 'same-origin', redirect: 'manual' }
  if (method !== 'GET' && method !== 'HEAD') {
    if (session.csrf) headers['X-CSRF-Token'] = session.csrf
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json'
      init.body = JSON.stringify(body)
    }
  }
  let res
  try {
    res = await fetch(path + qs(params), init)
  } catch {
    throw new ApiError(0, 'Serveur injoignable.')
  }
  if (res.status === 401) {
    if (!quiet401) onUnauthorized()
    throw new ApiError(401, MESSAGES[401])
  }
  if (res.status === 204) return null
  let data = null
  try {
    data = await res.json()
  } catch {
    /* corps non JSON */
  }
  if (!res.ok) {
    // Messages génériques : on n'affiche jamais le détail brut renvoyé par le serveur
    const extra = typeof data?.detail === 'string' && res.status !== 500 ? ` ${data.detail}` : ''
    throw new ApiError(res.status, (MESSAGES[res.status] || 'Erreur inattendue.') + (res.status === 422 || res.status === 409 ? extra : ''), data)
  }
  return data
}

export const get = (path, params) => api('GET', path, { params })
export const post = (path, body, opts) => api('POST', path, { body, ...opts })
export const put = (path, body) => api('PUT', path, { body })
export const del = (path) => api('DELETE', path)
