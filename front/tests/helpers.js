import { vi } from 'vitest'
import { createRouter, createMemoryHistory } from 'vue-router'
import { routes, permissionGuard } from '../src/router.js'
import { session, setMe, clearSession } from '../src/stores/session.js'

export const PERMS = {
  viewer: ['search', 'topology:read'],
  operator: ['search', 'topology:read', 'realtime', 'export'],
  admin: ['inventory:read', 'inventory:write', 'credentials:write', 'backups:read', 'backups:run', 'tokens:manage', 'auth:manage', 'ports:configure', 'topology:read', 'search', 'realtime', 'export', 'audit:read', 'settings:write'],
}

export function login(role = 'admin') {
  setMe({ user_id: 'u1', label: `${role}@example.org`, role, permissions: PERMS[role], csrf_token: 'csrf-123' })
}

export function logout() {
  clearSession()
}

export async function makeRouter(path = '/') {
  const router = createRouter({ history: createMemoryHistory(), routes })
  router.beforeEach(permissionGuard)
  router.push(path)
  await router.isReady()
  return router
}

// Réponse fetch simulée ; `handler(url, init)` retourne [status, body] ou un objet Response
export function mockFetch(handler) {
  const calls = []
  const fn = vi.fn(async (url, init = {}) => {
    calls.push({ url, init })
    const r = await handler(String(url), init)
    const [status, body] = Array.isArray(r) && typeof r[0] === 'number' && r.length === 2 ? r : [200, r]
    return { status, ok: status >= 200 && status < 300, json: async () => body }
  })
  vi.stubGlobal('fetch', fn)
  return { calls, fn }
}

export const flush = () => new Promise((r) => setTimeout(r, 0))
export { session }
