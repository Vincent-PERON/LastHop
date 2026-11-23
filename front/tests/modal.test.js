import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import Modal from '../src/components/Modal.vue'
import PortEndpointsModal from '../src/components/PortEndpointsModal.vue'
import DeviceView from '../src/views/DeviceView.vue'
import { login, logout, makeRouter, mockFetch, flush } from './helpers.js'

afterEach(() => { logout(); document.body.innerHTML = ''; document.body.className = '' })

describe('Modal', () => {
  it('est un dialogue accessible, se ferme avec Échap, le fond ou la croix, et rend le focus', async () => {
    const trigger = document.createElement('button')
    document.body.appendChild(trigger)
    trigger.focus()
    const w = mount(Modal, { props: { title: 'Titre' }, slots: { default: '<button class="inside">ok</button>' }, attachTo: document.body })
    await flush()
    const dlg = w.find('[role="dialog"]')
    expect(dlg.attributes('aria-modal')).toBe('true')
    expect(w.find(`#${dlg.attributes('aria-labelledby')}`).text()).toBe('Titre')
    expect(document.activeElement.getAttribute('aria-label')).toBe('Fermer') // focus placé dans la fenêtre
    expect(document.body.classList.contains('modal-open')).toBe(true)
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await w.find('.modal-backdrop').trigger('mousedown')
    await w.find('.modal-close').trigger('click')
    expect(w.emitted('close')).toHaveLength(3)
    w.unmount()
    expect(document.activeElement).toBe(trigger) // focus rendu à l'élément qui a ouvert la fenêtre
    expect(document.body.classList.contains('modal-open')).toBe(false)
  })

  it('piège la tabulation dans la fenêtre', async () => {
    const w = mount(Modal, { props: { title: 'T' }, slots: { default: '<button class="last">x</button>' }, attachTo: document.body })
    await flush()
    const last = w.find('.last').element
    last.focus()
    const ev = new KeyboardEvent('keydown', { key: 'Tab', cancelable: true })
    document.dispatchEvent(ev)
    expect(ev.defaultPrevented).toBe(true)
    expect(document.activeElement.getAttribute('aria-label')).toBe('Fermer') // retour au premier élément
    w.unmount()
  })

  it('un clic DANS la fenêtre ne la ferme pas', async () => {
    const w = mount(Modal, { props: { title: 'T' }, slots: { default: '<p class="p">x</p>' } })
    await w.find('.p').trigger('mousedown')
    expect(w.emitted('close')).toBeUndefined()
  })
})

describe('PortEndpointsModal', () => {
  const device = { id: 'd1', name: 'sw-1' }
  const port = { id: 'p10', name: 'Gi1/0/1', oper_status: 1, role: 'access', alias: '<b>compta</b>' }

  async function open(handler, p = port) {
    login('admin')
    const m = mockFetch(handler)
    const router = await makeRouter('/devices/d1')
    const w = mount(PortEndpointsModal, { props: { device, port: p }, global: { plugins: [router] }, attachTo: document.body })
    await flush(); await flush()
    return { w, ...m }
  }

  it('charge les endpoints du port par son identifiant exact et les affiche en texte', async () => {
    const { w, calls } = await open(() => ({ total: 1, items: [{ id: 'e1', mac: '02:bb:00:00:00:01', ip: '10.0.0.5', hostname: '<img src=x onerror=alert(1)>', vendor: null, vlan: 10, last_seen: '2026-11-22T10:00:00Z', active: true }] }))
    expect(calls[0].url).toContain('interface_id=p10')
    expect(calls[0].url).not.toContain('port=') // pas de filtre en sous-chaîne
    expect(w.find('[role="dialog"]').exists()).toBe(true)
    expect(w.find('h2').text()).toBe('Endpoints du port Gi1/0/1')
    expect(w.text()).toContain('02:bb:00:00:00:01')
    expect(w.text()).toContain('<img src=x onerror=alert(1)>')
    expect(w.find('img').exists()).toBe(false)
    expect(w.text()).toContain('<b>compta</b>') // alias du port en texte
    expect(w.find('b').exists()).toBe(false)
  })

  it('état vide, explication pour un uplink et lien vers la recherche complète', async () => {
    const { w } = await open(() => ({ total: 0, items: [] }), { ...port, role: 'uplink' })
    expect(w.text()).toContain('Aucun endpoint connu sur ce port')
    expect(w.text()).toContain('Ce port est un uplink')
    const link = w.find('.modal-foot a')
    expect(link.text()).toContain('Ouvrir dans la recherche complète')
    await link.trigger('click')
    expect(w.emitted('close')).toHaveLength(1)
  })

  it('pagine et affiche une erreur générique', async () => {
    const { w, calls } = await open((url) => (url.includes('offset=10') ? [500, { detail: 'secret' }] : { total: 25, items: [] }))
    await w.find('button[aria-label="Page suivante"]').trigger('click')
    await flush()
    expect(calls.at(-1).url).toContain('offset=10')
    expect(w.find('[role="alert"]').text()).not.toContain('secret')
  })
})

describe('fiche équipement : endpoints d’un port en modale', () => {
  const ports = [
    { id: 'p1', if_index: 1, name: 'Gi1/0/1', alias: '', oper_status: 1, role: 'access', mac_count: 2, neighbors: [] },
    { id: 'p2', if_index: 2, name: 'Gi1/0/10', alias: '', oper_status: 1, role: 'access', mac_count: 1, neighbors: [] },
  ]
  async function mountDevice(path) {
    login('admin')
    mockFetch((url) => {
      if (url.endsWith('/interfaces')) return [200, ports]
      if (url.startsWith('/api/v1/endpoints')) return { total: 1, items: [{ id: 'e', mac: '02:aa:00:00:00:01', ip: null, vlan: null, last_seen: '2026-11-22T10:00:00Z', active: true }] }
      return [200, { id: 'd1', name: 'sw-1', mgmt_ip: '10.0.0.1', role: 'access', driver: 'cisco_ios', ports_up: 2, ports_down: 0 }]
    })
    const router = await makeRouter(path)
    const w = mount(DeviceView, { global: { plugins: [router] }, attachTo: document.body })
    await flush(); await flush()
    return { w, router }
  }

  it('un clic sur une tuile de port ouvre la modale (sans changer de page) et Échap la ferme', async () => {
    const { w, router } = await mountDevice('/devices/d1')
    expect(w.find('[role="dialog"]').exists()).toBe(false)
    await w.findAll('button.tile')[0].trigger('click')
    await flush(); await flush()
    expect(w.find('[role="dialog"]').exists()).toBe(true)
    expect(w.find('h2#' + w.find('[role="dialog"]').attributes('aria-labelledby')).text()).toContain('Gi1/0/1')
    expect(router.currentRoute.value.name).toBe('device') // pas de navigation
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flush()
    expect(w.find('[role="dialog"]').exists()).toBe(false)
  })

  it('l’onglet Ports propose un bouton « Endpoints » par port qui ouvre la modale', async () => {
    const { w } = await mountDevice('/devices/d1?tab=ports')
    const btn = w.find('button[aria-label="Voir les endpoints du port Gi1/0/10"]')
    expect(btn.exists()).toBe(true)
    expect(w.findAll('tbody a[href*="/search"]')).toHaveLength(0) // plus de lien vers une autre page
    await btn.trigger('click')
    await flush(); await flush()
    expect(w.find('.modal h2').text()).toBe('Endpoints du port Gi1/0/10')
  })
})
