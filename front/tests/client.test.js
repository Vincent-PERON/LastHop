import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { api, get, post, qs, setUnauthorizedHandler, ApiError } from '../src/api/client.js'
import { login, logout, mockFetch } from './helpers.js'

beforeEach(() => login('admin'))
afterEach(() => {
  vi.unstubAllGlobals()
  logout()
})

describe('client API', () => {
  it('GET : cookie de même origine, pas d’en-tête CSRF, pas de suivi de redirection', async () => {
    const { calls } = mockFetch(() => [200, { ok: 1 }])
    await get('/api/v1/x', { a: 1 })
    expect(calls[0].url).toBe('/api/v1/x?a=1')
    expect(calls[0].init.credentials).toBe('same-origin')
    expect(calls[0].init.redirect).toBe('manual')
    expect(calls[0].init.headers['X-CSRF-Token']).toBeUndefined()
  })

  it('POST/PUT/DELETE : jeton CSRF de la session et corps JSON', async () => {
    const { calls } = mockFetch(() => [200, {}])
    await post('/api/v1/x', { a: 1 })
    await api('DELETE', '/api/v1/x/1')
    expect(calls[0].init.headers['X-CSRF-Token']).toBe('csrf-123')
    expect(calls[0].init.headers['Content-Type']).toBe('application/json')
    expect(calls[0].init.body).toBe('{"a":1}')
    expect(calls[1].init.headers['X-CSRF-Token']).toBe('csrf-123')
  })

  it('401 : déclenche la reconnexion', async () => {
    const handler = vi.fn()
    setUnauthorizedHandler(handler)
    mockFetch(() => [401, { detail: 'x' }])
    await expect(get('/api/v1/x')).rejects.toMatchObject({ status: 401 })
    expect(handler).toHaveBeenCalledOnce()
  })

  it('n’affiche jamais le détail d’une erreur serveur (500) ; affiche le message générique d’un 409/422', async () => {
    mockFetch(() => [500, { detail: 'Traceback: secret-password=hunter2' }])
    await expect(get('/x')).rejects.toSatisfy((e) => e instanceof ApiError && !e.message.includes('hunter2') && !e.message.includes('Traceback'))
    mockFetch(() => [409, { detail: 'Ce nom existe déjà' }])
    await expect(post('/x', {})).rejects.toThrow(/Ce nom existe déjà/)
  })

  it('erreur réseau : message clair', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('boom') }))
    await expect(get('/x')).rejects.toMatchObject({ status: 0, message: 'Serveur injoignable.' })
  })

  it('qs : ignore les valeurs vides et encode', () => {
    expect(qs({ a: '', b: null, c: undefined, d: 'x y&z', e: 0 })).toBe('?d=x+y%26z&e=0')
    expect(qs({})).toBe('')
  })
})
