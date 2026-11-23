import { describe, it, expect, afterEach } from 'vitest'
import { firstAllowed } from '../src/router.js'
import { can, loginUrl } from '../src/stores/session.js'
import { login, logout, makeRouter } from './helpers.js'

afterEach(logout)

describe('permissions et routes', () => {
  it('page d’accueil selon le rôle', () => {
    login('viewer')
    expect(firstAllowed()).toBe('/search') // pas de tableau de bord : recherche et topologie seulement
    expect(can('realtime')).toBe(false)
    login('admin')
    expect(firstAllowed()).toBe('/dashboard')
    expect(can('audit:read')).toBe(true)
  })

  it('refuse les routes sans permission (la vraie autorisation reste côté serveur)', async () => {
    login('viewer')
    expect((await makeRouter('/locate')).currentRoute.value.name).toBe('forbidden')
    expect((await makeRouter('/admin/audit')).currentRoute.value.name).toBe('forbidden')
    expect((await makeRouter('/admin/credentials')).currentRoute.value.name).toBe('forbidden')
    expect((await makeRouter('/search')).currentRoute.value.name).toBe('search')
  })

  it('opérateur : temps réel oui, administration non', async () => {
    login('operator')
    expect((await makeRouter('/locate')).currentRoute.value.name).toBe('locate')
    expect((await makeRouter('/admin/settings')).currentRoute.value.name).toBe('forbidden')
  })

  it('hors super admin : seulement recherche et topologie (pas d’inventaire, sauvegardes, profils, audit, tokens)', async () => {
    for (const role of ['viewer', 'operator']) {
      login(role)
      expect((await makeRouter('/search')).currentRoute.value.name).toBe('search')
      expect((await makeRouter('/topology')).currentRoute.value.name).toBe('topology')
      for (const p of ['/dashboard', '/devices', '/devices/d1', '/backups', '/admin/credentials', '/admin/ssh', '/admin/discovery', '/admin/settings', '/admin/audit', '/tokens']) {
        expect((await makeRouter(p)).currentRoute.value.name, `${role} ${p}`).toBe('forbidden')
      }
    }
    login('admin')
    for (const p of ['/dashboard', '/devices', '/backups', '/admin/ssh', '/admin/audit', '/tokens']) {
      expect((await makeRouter(p)).currentRoute.value.name, p).not.toBe('forbidden')
    }
  })

  it('URL de connexion : uniquement un chemin interne (pas de redirection ouverte)', () => {
    expect(loginUrl('/search?q=1')).toBe('/api/v1/auth/login?next=%2Fsearch%3Fq%3D1')
    expect(loginUrl('//evil.example')).toBe('/api/v1/auth/login?next=%2F')
    expect(loginUrl('https://evil.example')).toBe('/api/v1/auth/login?next=%2F')
  })
})
