import { describe, it, expect, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import App from '../src/App.vue'
import { login, logout, makeRouter, flush } from './helpers.js'

afterEach(logout)

async function nav(role) {
  login(role)
  const router = await makeRouter('/search')
  const w = mount(App, { global: { plugins: [router] } })
  await flush()
  return { w, links: w.findAll('.sidebar .nav-item').map((a) => a.text()) }
}

describe('menu latéral selon le rôle', () => {
  it('lecteur : recherche et topologie uniquement', async () => {
    const { w, links } = await nav('viewer')
    expect(links).toEqual(['Recherche', 'Topologie'])
    expect(w.find('.who em').text()).toBe('Lecteur')
  })

  it('opérateur : + localisation en direct, toujours aucune administration', async () => {
    const { links } = await nav('operator')
    expect(links).toEqual(['Recherche', 'Localiser', 'Topologie'])
  })

  it('super admin : tout, y compris profils, sauvegardes, paramètres, audit et tokens', async () => {
    const { w, links } = await nav('admin')
    for (const l of ['Profils SNMP', 'Profils SSH', 'Sauvegardes', 'Paramètres', 'Audit', 'Tokens API', 'Équipements']) {
      expect(links).toContain(l)
    }
    expect(w.find('.who em').text()).toBe('Super admin')
  })
})
