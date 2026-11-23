import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import SearchView from '../src/views/SearchView.vue'
import { login, logout, makeRouter, mockFetch, flush } from './helpers.js'

const ep = (i, over = {}) => ({ id: `e${i}`, mac: `02:bb:00:00:00:0${i}`, ip: `10.0.0.${i}`, vlan: 10, vendor: 'Bravo <b>Inc</b>', hostname: null, device: 'sw1', port: '4', first_seen: '2026-01-01T00:00:00Z', last_seen: '2026-01-02T00:00:00Z', active: true, ...over })

async function mountSearch(role, handler) {
  login(role)
  const m = mockFetch(handler)
  const router = await makeRouter('/search')
  const w = mount(SearchView, { global: { plugins: [router] } })
  await flush()
  await flush()
  return { w, ...m, router }
}

afterEach(logout)

describe('SearchView', () => {
  it('affiche les résultats, échappe les données non fiables, pagine', async () => {
    const { w, calls } = await mountSearch('operator', (url) => {
      if (url.startsWith('/api/v1/endpoints/e1/history')) return [200, [{ ts: '2026-01-01T00:00:00Z', change: 'appeared', old: null, new: { device: 'sw1', port: '4' } }]]
      return { total: 60, items: [ep(1), ep(2)] }
    })
    expect(w.findAll('tbody tr')).toHaveLength(2)
    expect(w.text()).toContain('Bravo <b>Inc</b>') // texte littéral
    expect(w.find('b').exists()).toBe(false)
    expect(w.text()).toContain('60 résultat(s)')
    await w.find('button[aria-label="Page suivante"]').trigger('click')
    await flush()
    expect(calls.at(-1).url).toContain('offset=25')
  })

  it('envoie la recherche globale et affiche l’historique d’un endpoint', async () => {
    const { w, calls } = await mountSearch('operator', (url) => (url.includes('/history') ? [200, [{ ts: '2026-01-01T00:00:00Z', change: 'moved', old: { device: 'a', port: '1' }, new: { device: 'b', port: '2' } }]] : { total: 1, items: [ep(1)] }))
    await w.find('input[type="search"]').setValue('02bb')
    await w.find('form').trigger('submit')
    await flush()
    expect(calls.some((c) => c.url.includes('q=02bb'))).toBe(true)
    await w.find('tbody tr').trigger('click')
    await flush()
    expect(w.find('aside').text()).toContain('moved')
    expect(w.find('aside').text()).toContain('a 1 → b 2')
  })

  it('export CSV : visible seulement avec la permission « export »', async () => {
    const viewer = await mountSearch('viewer', () => ({ total: 0, items: [] }))
    expect(viewer.w.text()).not.toContain('Exporter en CSV')
    logout()
    const op = await mountSearch('operator', () => ({ total: 0, items: [] }))
    const a = op.w.find('a[download]')
    expect(a.exists()).toBe(true)
    expect(a.attributes('href')).toMatch(/^\/api\/v1\/endpoints\/export\.csv/)
  })

  it('affiche une erreur générique si l’API échoue', async () => {
    const { w } = await mountSearch('viewer', () => [500, { detail: 'secret stack trace' }])
    expect(w.find('[role="alert"]').text()).not.toContain('secret')
  })
})
