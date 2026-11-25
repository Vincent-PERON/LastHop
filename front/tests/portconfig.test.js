import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import PortConfigModal from '../src/components/PortConfigModal.vue'
import { login, logout, mockFetch, flush } from './helpers.js'

afterEach(logout)

const DEVICE = { id: 'd1', name: 'sw-acc' }
const VLANS = [{ id: 1, name: 'default' }, { id: 10, name: 'USERS' }, { id: 20, name: 'VOICE' }]
const PLAN = (over = {}) => ({ plan_id: 'p'.repeat(30), commands: ['configure terminal', 'interface Gi1/0/5', 'switchport access vlan 20', 'end'], save_commands: ['write memory'], desired: { mode: 'access', access_vlan: 20 }, alerts: [{ level: 'info', text: 'La session SSH de LastHop peut passer par ce port.' }], requires_ack: false, ack_phrase: null, ...over })

async function open(port, handler) {
  login('admin')
  const m = mockFetch((url, init) => (url.endsWith('/vlans') ? VLANS : handler(url, init)))
  const w = mount(PortConfigModal, { props: { device: DEVICE, port }, attachTo: document.body })
  await flush(); await flush()
  return { w, ...m }
}
const dlg = () => document.body.querySelector('[role="dialog"]')
const btn = (text) => [...dlg().querySelectorAll('button')].find((b) => b.textContent.includes(text))

describe('configuration d’un port', () => {
  it('ne propose que les VLAN connus de l’équipement et n’envoie rien avant l’aperçu', async () => {
    const { w, calls } = await open({ id: 'i1', name: 'Gi1/0/5', port_mode: 'access', pvid: 10, tagged_vlans: [] }, () => ({}))
    const opts = [...dlg().querySelectorAll('select option')].map((o) => o.textContent.trim())
    expect(opts).toEqual(expect.arrayContaining(['10 — USERS', '20 — VOICE', '1 — default']))
    expect(opts.some((o) => o.startsWith('99'))).toBe(false)
    expect(dlg().textContent).toContain('Accès · VLAN 10')
    expect(calls.filter((c) => c.init.method === 'POST')).toHaveLength(0)
    w.unmount()
  })

  it('port d’accès : aperçu des commandes, relecture obligatoire, puis application et relecture de l’état', async () => {
    const { w, calls } = await open({ id: 'i1', name: 'Gi1/0/5', port_mode: 'access', pvid: 10, tagged_vlans: [] }, (url, init) => {
      if (url.endsWith('/port-config/preview')) return PLAN()
      if (url.endsWith('/port-config/apply')) return [202, { job_id: 'j9' }]
      if (url.endsWith('/jobs/j9')) return { status: 'done', result: { ok: true, saved: true, message: 'Modification appliquée.', steps: [{ command: 'configure terminal', output: '' }] } }
      if (url.endsWith('/topology')) return [202, { job_id: 't1' }]
      if (url.endsWith('/jobs/t1')) return { status: 'done', result: {} }
      return init.method === 'GET' ? {} : {}
    })
    const sel = dlg().querySelector('select')
    sel.value = '20'; sel.dispatchEvent(new Event('change')); await flush()
    btn('Aperçu').click(); await flush(); await flush()
    const pre = JSON.parse(calls.find((c) => c.url.endsWith('/port-config/preview')).init.body)
    expect(pre).toEqual({ mode: 'access', access_vlan: 20, save: true })
    expect(dlg().querySelector('pre.config').textContent).toContain('switchport access vlan 20')
    expect(btn('Appliquer').disabled).toBe(true) // il faut relire les commandes
    const cb = dlg().querySelector('input[type="checkbox"]'); cb.checked = true; cb.dispatchEvent(new Event('change')); await flush()
    expect(btn('Appliquer').disabled).toBe(false)
    btn('Appliquer').click(); await flush(); await flush(); await flush(); await flush()
    const ap = JSON.parse(calls.find((c) => c.url.endsWith('/port-config/apply')).init.body)
    expect(ap).toEqual({ plan_id: 'p'.repeat(30), acknowledge: null })
    expect(dlg().textContent).toContain('Modification appliquée.')
    expect(calls.some((c) => c.url.endsWith('/devices/d1/topology'))).toBe(true) // l'état réel est relu
    expect(w.emitted('changed')).toBeTruthy()
    w.unmount()
  })

  it('uplink : alerte rouge et confirmation par saisie exacte du nom du port', async () => {
    const { w, calls } = await open({ id: 'i2', name: 'Gi1/0/1', port_mode: 'trunk', pvid: 1, tagged_vlans: [10] }, (url) => {
      if (url.endsWith('/port-config/preview')) return PLAN({ requires_ack: true, ack_phrase: 'Gi1/0/1', alerts: [{ level: 'danger', text: 'Le port Gi1/0/1 est un port d’UPLINK vers sw-core.' }] })
      if (url.endsWith('/port-config/apply')) return [202, { job_id: 'j8' }]
      return { status: 'done', result: { ok: true, steps: [], message: 'ok' } }
    })
    expect(dlg().querySelector('input[type="radio"][value="trunk"]').checked).toBe(true) // mode actuel présélectionné
    btn('Aperçu').click(); await flush(); await flush()
    expect(dlg().querySelector('.alert-danger').textContent).toContain('UPLINK')
    expect(dlg().querySelector('.confirm-danger').textContent).toContain('Gi1/0/1')
    const input = dlg().querySelector('.confirm-danger input')
    for (const wrong of ['', 'gi1/0/1', 'Gi1/0/2', 'Gi1/0/1 ']) {
      input.value = wrong; input.dispatchEvent(new Event('input')); await flush()
      expect(btn('Appliquer').disabled, wrong).toBe(true)
    }
    input.value = 'Gi1/0/1'; input.dispatchEvent(new Event('input')); await flush()
    expect(btn('Appliquer').disabled).toBe(false)
    btn('Appliquer').click(); await flush(); await flush()
    expect(JSON.parse(calls.find((c) => c.url.endsWith('/port-config/apply')).init.body).acknowledge).toBe('Gi1/0/1')
    w.unmount()
  })

  it('refus de l’équipement : message humain, conseil et détail affichés en texte', async () => {
    const { w } = await open({ id: 'i1', name: 'Gi1/0/5', port_mode: 'access', pvid: 10, tagged_vlans: [] }, (url) => {
      if (url.endsWith('/port-config/preview')) return PLAN()
      if (url.endsWith('/port-config/apply')) return [202, { job_id: 'j7' }]
      return { status: 'failed', result: { ok: false, message: 'L’équipement a refusé une commande.', advice: 'Vérifiez le port.', detail: '<img src=x onerror=alert(1)> Invalid input', steps: [{ command: 'switchport access vlan 20', output: 'Invalid input' }] } }
    })
    const sel = dlg().querySelector('select'); sel.value = '20'; sel.dispatchEvent(new Event('change')); await flush()
    btn('Aperçu').click(); await flush(); await flush()
    const cb = dlg().querySelector('input[type="checkbox"]'); cb.checked = true; cb.dispatchEvent(new Event('change')); await flush()
    btn('Appliquer').click(); await flush(); await flush(); await flush()
    expect(dlg().textContent).toContain('a refusé une commande')
    expect(dlg().textContent).toContain('<img src=x onerror=alert(1)>')
    expect(dlg().querySelector('img')).toBeNull()
    w.unmount()
  })

  it('erreur de validation du serveur : affichée, aucune commande appliquée', async () => {
    const { w, calls } = await open({ id: 'i1', name: 'Gi1/0/5', port_mode: 'access', pvid: 10, tagged_vlans: [] }, (url) => (url.endsWith('/port-config/preview') ? [422, { detail: 'Le VLAN 99 n’existe pas sur cet équipement.' }] : {}))
    const sel = dlg().querySelector('select'); sel.value = '20'; sel.dispatchEvent(new Event('change')); await flush()
    btn('Aperçu').click(); await flush(); await flush()
    expect(dlg().textContent).toContain('n’existe pas sur cet équipement')
    expect(calls.some((c) => c.url.endsWith('/port-config/apply'))).toBe(false)
    w.unmount()
  })
})
