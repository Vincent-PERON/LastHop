import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import LocateView from '../src/views/LocateView.vue'
import { login, logout, makeRouter, mockFetch, flush } from './helpers.js'

// Faux EventSource contrôlable par les tests
class FakeES {
  static last = null
  constructor(url, opts) {
    this.url = url
    this.opts = opts
    this.listeners = {}
    this.readyState = 1
    this.closed = false
    FakeES.last = this
  }
  addEventListener(t, fn) { (this.listeners[t] ||= []).push(fn) }
  close() { this.closed = true; this.readyState = 2 }
  emit(type, data) { (this.listeners[type] || []).forEach((fn) => fn({ data: JSON.stringify(data) })) }
}

async function start(handler = () => [202, { job_id: 'j1', events_url: '/api/v1/realtime/j1/events' }], q = '10.50.0.30') {
  login('operator')
  vi.stubGlobal('EventSource', FakeES)
  const m = mockFetch((url) => (url === '/api/v1/sites' ? [200, [{ id: 's1', name: 'Siège' }]] : handler(url)))
  const router = await makeRouter(`/locate?q=${q}`)
  const w = mount(LocateView, { global: { plugins: [router] } })
  await flush()
  await w.find('form').trigger('submit')
  await flush()
  return { w, ...m }
}

afterEach(() => { logout(); vi.unstubAllGlobals(); FakeES.last = null })

describe('LocateView', () => {
  it('préremplit la requête, lance la recherche et ouvre le flux SSE', async () => {
    const { w, calls } = await start()
    expect(w.find('input').element.value).toBe('10.50.0.30')
    const post = calls.find((c) => c.url === '/api/v1/realtime')
    expect(JSON.parse(post.init.body)).toEqual({ query: '10.50.0.30' })
    expect(post.init.headers['X-CSRF-Token']).toBe('csrf-123')
    expect(FakeES.last.url).toBe('/api/v1/realtime/j1/events')
  })

  it('affiche la progression puis le résultat et la chaîne d’uplinks', async () => {
    const { w } = await start()
    const es = FakeES.last
    es.emit('started', { query: '10.50.0.30' })
    es.emit('arp_resolved', { mac: '02:cc:00:00:00:00', gateway: 'rtr' })
    es.emit('fdb_querying', {})
    es.emit('device_queried', { device: 'sw-a', status: 'found', port: '4' })
    es.emit('device_queried', { device: 'sw-b', status: 'error', code: 'DEVICE_UNREACHABLE' })
    es.emit('hop', { depth: 1, device: 'sw-core', port: 'Gi1/0/2', role: 'uplink' })
    await flush()
    expect(w.text()).toContain('MAC trouvée : 02:cc:00:00:00:00 (via rtr)')
    expect(w.text()).toContain('Équipement injoignable')
    es.emit('located', { ok: true, mac: '02:cc:00:00:00:00', ip: '10.50.0.30', location: { device: 'sw-a', port: '4', vlan: 10 }, chain: [{ device: 'sw-core', port: 'Gi1/0/2' }], vendor: '<img src=x onerror=alert(1)>', warnings: [{ message: 'attention' }], elapsed_ms: 1200 })
    es.emit('done', { ok: true })
    await flush()
    expect(w.find('.result.ok h2').text()).toBe('sw-a — port 4')
    expect(w.findAll('.chain li')).toHaveLength(2)
    expect(w.text()).toContain('<img src=x onerror=alert(1)>') // texte, pas d'élément
    expect(w.find('img').exists()).toBe(false)
    expect(es.closed).toBe(true)
    expect(w.find('button[type="submit"]').attributes('disabled')).toBeUndefined()
  })

  it('affiche un échec explicite (code et message du serveur)', async () => {
    const { w } = await start()
    FakeES.last.emit('failed', { error_code: 'MAC_AGED_OUT', message: 'La MAC est apprise nulle part.' })
    FakeES.last.emit('done', { ok: false })
    await flush()
    expect(w.find('.result.bad').text()).toContain('MAC expirée')
    expect(w.find('.result.bad').text()).toContain('apprise nulle part')
  })

  it('limite de débit (429) : message clair, aucun flux ouvert', async () => {
    const { w } = await start(() => [429, { detail: 'x' }])
    expect(w.find('[role="alert"]').text()).toContain('Trop de requêtes')
    expect(FakeES.last).toBeNull()
  })

  it('session expirée pendant le flux et annulation', async () => {
    const { w } = await start()
    FakeES.last.emit('auth_expired', {})
    await flush()
    expect(w.find('[role="alert"]').text()).toContain('Session expirée')
    const es2 = (await start()).w
    const stream = FakeES.last
    await es2.find('button.link').trigger('click')
    expect(stream.closed).toBe(true)
  })

  it('ferme le flux quand on quitte la page', async () => {
    const { w } = await start()
    const es = FakeES.last
    w.unmount()
    expect(es.closed).toBe(true)
  })
})
