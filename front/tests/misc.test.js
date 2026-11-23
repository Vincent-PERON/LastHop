import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { buildElements } from '../src/utils/topology.js'
import TokensView from '../src/views/TokensView.vue'
import { login, logout, makeRouter, mockFetch, flush } from './helpers.js'

afterEach(() => { logout(); vi.unstubAllGlobals() })

describe('topologie', () => {
  it('construit les éléments Cytoscape et ignore les liaisons orphelines', () => {
    const els = buildElements({
      nodes: [{ id: 'a', label: 'sw-a', role: 'core', managed: true }, { id: 'b', name: 'sw-b', role: 'access' }, { id: 'ext:x', label: 'phone', managed: false }],
      edges: [{ id: 'e1', source: 'a', target: 'b', source_port: 'Gi1', target_port: '1', protocols: ['lldp', 'cdp'] }, { id: 'e2', source: 'a', target: 'zzz' }],
    })
    expect(els.filter((e) => e.data.source)).toHaveLength(1)
    expect(els.find((e) => e.data.id === 'e1').data).toMatchObject({ label: 'Gi1 ↔ 1', protocols: 'lldp/cdp' })
    expect(els.find((e) => e.data.id === 'ext:x').data).toMatchObject({ managed: false, role: 'external' })
    expect(els.find((e) => e.data.id === 'b').data.label).toBe('sw-b')
  })
})

describe('TokensView', () => {
  it('affiche le secret une seule fois, uniquement en mémoire', async () => {
    login('admin')
    const store = vi.spyOn(Storage.prototype, 'setItem')
    mockFetch((url, init) => (init.method === 'POST' ? [201, { id: 't1', token: 'lasthop_deadbeef.SECRET', scopes: ['search'] }] : [200, []]))
    const router = await makeRouter('/tokens')
    const w = mount(TokensView, { global: { plugins: [router] } })
    await flush()
    await w.find('input[pattern]').setValue('ci')
    await w.find('form').trigger('submit')
    await flush()
    expect(w.find('.secret').text()).toBe('lasthop_deadbeef.SECRET')
    expect(store).not.toHaveBeenCalled() // rien dans localStorage/sessionStorage
    w.unmount()
    expect(document.body.textContent).not.toContain('SECRET')
  })
})
