import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import Pager from '../src/components/Pager.vue'
import PortGrid from '../src/components/PortGrid.vue'
import PortBar from '../src/components/PortBar.vue'
import PageHeader from '../src/components/PageHeader.vue'
import DashboardView from '../src/views/DashboardView.vue'
import DevicesView from '../src/views/DevicesView.vue'
import DeviceView from '../src/views/DeviceView.vue'
import DeviceDiagnostic from '../src/components/DeviceDiagnostic.vue'
import { login, logout, makeRouter, mockFetch, flush } from './helpers.js'

afterEach(logout)

const DEVICE = (i, over = {}) => ({ id: `d${i}`, name: `sw-${i}`, mgmt_ip: `10.0.0.${i}`, role: 'access', driver: 'cisco_ios', vendor: 'Cisco', model: 'C2960X', snmp_version: 'v3', ports_up: 10 + i, ports_down: i, ports_total: 10 + 2 * i, last_topology_status: 'ok', last_topology_at: '2026-11-22T10:00:00Z', last_backup_status: null, site_id: null, ...over })

describe('Pager', () => {
  it('affiche les pages, l’intervalle et change de page / de taille', async () => {
    const w = mount(Pager, { props: { total: 95, offset: 25, limit: 25 } })
    expect(w.text()).toContain('Affichage de 26 à 50 sur 95 entrée(s)')
    expect(w.find('.pages button.on').text()).toBe('2')
    await w.find('button[aria-label="Page suivante"]').trigger('click')
    expect(w.emitted('change')[0]).toEqual([50])
    await w.findAll('.sizes button').find((b) => b.text() === '50').trigger('click')
    expect(w.emitted('limit')[0]).toEqual([50])
    await w.setProps({ offset: 0 })
    expect(w.find('button[aria-label="Page précédente"]').attributes('disabled')).toBeDefined()
  })

  it('résume les longues listes avec des points de suspension', () => {
    const w = mount(Pager, { props: { total: 1000, offset: 500, limit: 10 } })
    expect(w.find('.gap').exists()).toBe(true)
    expect(w.text()).toContain('Affichage de 501 à 510 sur 1000')
  })
})

describe('composants visuels', () => {
  it('PortBar : chiffres up/down lisibles sans couleur', () => {
    const w = mount(PortBar, { props: { up: 38, down: 10 } })
    expect(w.find('.up').text()).toBe('38')
    expect(w.find('.down').text()).toBe('10')
    expect(w.attributes('title')).toBe('38 ports up, 10 ports down')
  })

  it('PortGrid : états up/down/uplink, nom hostile en texte, sélection', async () => {
    const ports = [
      { id: 'a', name: 'Gi1/0/1', oper_status: 1, role: 'access', alias: '' },
      { id: 'b', name: 'Gi1/0/2', oper_status: 2, role: 'uplink', alias: '<script>x</script>' },
    ]
    const w = mount(PortGrid, { props: { ports } })
    const tiles = w.findAll('button.tile')
    expect(tiles[0].classes()).toContain('up')
    expect(tiles[1].classes()).toEqual(expect.arrayContaining(['down', 'uplink']))
    expect(tiles[1].attributes('title')).toContain('<script>x</script>') // attribut texte, jamais exécuté
    expect(w.find('script').exists()).toBe(false)
    await tiles[1].trigger('click')
    expect(w.emitted('select')[0][0].id).toBe('b')
  })

  it('PageHeader : fil d’Ariane, titre, compteurs et onglets', async () => {
    const router = await makeRouter('/')
    const w = mount(PageHeader, { props: { title: 'Équipements', crumbs: [{ label: 'LastHop', to: '/' }], kpis: [{ value: 7, label: 'Ports up' }], tabs: [{ label: 'Résumé', to: '/', active: true }] }, global: { plugins: [router] } })
    expect(w.find('h1').text()).toBe('Équipements')
    expect(w.find('.kpi dd').text()).toBe('7')
    expect(w.find('.tabs a.active').text()).toBe('Résumé')
  })
})

describe('vues', () => {
  it('liste des équipements : compteurs de ports, pilote en pastilles, filtre et actions selon le rôle', async () => {
    login('admin')
    mockFetch((url) => (url === '/api/v1/devices' ? [200, [DEVICE(1), DEVICE(2, { driver: 'comware', last_topology_status: 'DEVICE_UNREACHABLE' })]] : [200, []]))
    const router = await makeRouter('/devices')
    const w = mount(DevicesView, { global: { plugins: [router] } })
    await flush(); await flush()
    expect(w.findAll('tbody tr')).toHaveLength(2)
    expect(w.find('.portbar .up').text()).toBe('11')
    expect(w.text()).toContain('SNMP v3')
    expect(w.text()).toContain('Cisco IOS')
    expect(w.text()).toContain('HPE Comware')
    expect(w.findAll('.kpi dd').map((x) => x.text())).toEqual(['2', '1', '23', '3']) // équipements, joignables, ports up, ports down
    expect(w.find('button[aria-label="Sauvegarder"]').exists()).toBe(true)
    await w.find('input[type="search"]').setValue('sw-2')
    expect(w.findAll('tbody tr')).toHaveLength(1)
  })

  it('ajout d’équipement dans une fenêtre modale : ouverture, erreur conservée, création puis fermeture', async () => {
    login('admin')
    mockFetch((url, init) => {
      if (init.method === 'POST' && url === '/api/v1/devices') return calls0.fail ? [422, { detail: 'IP invalide' }] : [201, { id: 'new' }]
      if (url === '/api/v1/credentials') return [{ id: 'c1', name: 'lab', version: 'v3' }]
      return url === '/api/v1/devices' ? [200, [DEVICE(1)]] : [200, []]
    })
    const calls0 = { fail: true }
    const router = await makeRouter('/devices')
    const w = mount(DevicesView, { global: { plugins: [router] }, attachTo: document.body })
    await flush(); await flush()
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    await w.findAll('button').find((b) => b.text().includes('Ajouter un équipement')).trigger('click')
    await flush()
    const dlg = document.body.querySelector('[role="dialog"]')
    expect(dlg).not.toBeNull()
    const set = async (label, v) => {
      const el = [...dlg.querySelectorAll('label')].find((l) => l.textContent.includes(label)).querySelector('input,select')
      el.value = v; el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input')); await flush()
    }
    await set('Nom', 'sw-new'); await set('IP de management', '10.0.0.9'); await set('Profil SNMP', 'c1')
    dlg.querySelector('form').dispatchEvent(new Event('submit'))
    await flush(); await flush()
    expect(document.body.querySelector('[role="dialog"]')).not.toBeNull() // échec : la fenêtre reste ouverte
    expect(dlg.textContent).toContain('IP invalide')
    expect(dlg.querySelector('input').value).toBe('sw-new') // saisie conservée
    calls0.fail = false
    dlg.querySelector('form').dispatchEvent(new Event('submit'))
    await flush(); await flush()
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    w.unmount()
  })

  it('un viewer ne voit aucune action d’administration', async () => {
    login('viewer')
    mockFetch(() => [200, [DEVICE(1)]])
    const router = await makeRouter('/devices')
    const w = mount(DevicesView, { global: { plugins: [router] } })
    await flush(); await flush()
    expect(w.find('.row-icons').exists()).toBe(false)
    expect(w.text()).not.toContain('Ajouter un équipement')
  })

  it('tableau de bord : indicateurs, équipements en alerte et dernières sauvegardes', async () => {
    login('admin')
    mockFetch((url) => {
      if (url === '/api/v1/devices') return [200, [DEVICE(1), DEVICE(2, { last_topology_status: 'DEVICE_UNREACHABLE', last_poll_status: null })]]
      if (url.startsWith('/api/v1/endpoints')) return { total: 42, items: [] }
      if (url.startsWith('/api/v1/backups/runs')) return { total: 1, items: [{ id: 'r', device: 'sw-2', device_id: 'd2', status: 'failed', summary: 'Sauvegarde échouée : refus', started_at: '2026-11-22T10:00:00Z' }] }
      return [200, {}]
    })
    const router = await makeRouter('/dashboard')
    const w = mount(DashboardView, { global: { plugins: [router] } })
    await flush(); await flush()
    expect(w.text()).toContain('42')
    expect(w.text()).toContain('Équipements à surveiller')
    expect(w.text()).toContain('DEVICE_UNREACHABLE')
    expect(w.text()).toContain('Sauvegarde échouée : refus')
    expect(w.findAll('.stat')).toHaveLength(4)
  })

  it('fiche équipement : résumé SNMP, grille de ports, onglets selon les droits', async () => {
    login('operator') // pas de droit « backups:read » : pas d'onglets Sauvegardes / Journaux
    mockFetch((url) => (url.endsWith('/interfaces') ? [200, [{ id: 'p1', if_index: 1, name: 'Gi1/0/1', alias: '', oper_status: 1, role: 'access', mac_count: 2, neighbors: [] }]] : [200, { ...DEVICE(1), sys_name: 'sw-1', sys_descr: 'Cisco IOS', chassis_mac: '00:11:22:33:44:55' }]))
    const router = await makeRouter('/devices/d1')
    const w = mount(DeviceView, { global: { plugins: [router] } })
    await flush(); await flush()
    expect(w.find('h1').text()).toContain('sw-1')
    expect(w.findAll('.tabs a').map((a) => a.text())).toEqual(['Résumé', 'Ports'])
    expect(w.text()).toContain('Informations SNMP')
    expect(w.findAll('.port-grid .tile')).toHaveLength(1)
    expect(w.text()).toContain('00:11:22:33:44:55')
  })
})

describe('Diagnostic SNMP', () => {
  it('lance le diagnostic et affiche conséquences, conseils et détail en texte', async () => {
    login('admin')
    const { calls } = mockFetch((url, init) => {
      if (url.endsWith('/diagnose')) return [202, { job_id: 'j1' }]
      if (url.endsWith('/jobs/j1')) return { status: 'done', result: {
        driver: 'fortinet',
        verdicts: [
          { feature: 'Apprentissage IP ↔ MAC (ARP)', level: 'ok', message: 'Table ARP lue.', advice: '' },
          { feature: 'Topologie (liaisons entre équipements)', level: 'missing', message: 'Aucun voisin LLDP/CDP.', advice: 'Activez LLDP <img src=x onerror=alert(1)>' },
        ],
        checks: [{ key: 'arp_media', title: 'ARP classique', status: 'ok', rows: 3, detail: '', sample: ['1.10.0.0.21 = 00:1a:2b'] }],
      } }
      return init.method === 'GET' ? DEVICE(1) : {}
    })
    const w = mount(DeviceDiagnostic, { props: { device: { id: 'd1', name: 'sw-1' } } })
    const btn = w.findAll('button').find((b) => b.text().includes('Lancer le diagnostic'))
    await btn.trigger('click')
    await flush(); await flush()
    expect(calls.some((c) => c.url.endsWith('/devices/d1/diagnose') && c.init.method === 'POST')).toBe(true)
    expect(w.text()).toContain('fortinet')
    expect(w.text()).toContain('Aucun voisin LLDP/CDP.')
    expect(w.text()).toContain('<img src=x onerror=alert(1)>') // texte, jamais du HTML
    expect(w.find('.advice img').exists()).toBe(false)
  })
})
