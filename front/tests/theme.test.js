import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ThemeMenu from '../src/components/ThemeMenu.vue'
import { theme, setTheme, initTheme, resolve } from '../src/stores/theme.js'
import { styleFor } from '../src/utils/topology.js'
import { flush } from './helpers.js'

function mockSystem(dark) {
  const listeners = []
  vi.stubGlobal('matchMedia', (q) => ({ matches: dark && q.includes('dark'), addEventListener: (_, fn) => listeners.push(fn), removeEventListener() {} }))
  return listeners
}

afterEach(() => {
  vi.unstubAllGlobals()
  window.localStorage.clear()
  document.documentElement.removeAttribute('data-theme')
})

describe('thème clair / sombre / système', () => {
  it('« système » suit le réglage du système d’exploitation', () => {
    mockSystem(true)
    expect(resolve('system')).toBe('dark')
    expect(resolve('light')).toBe('light')
    mockSystem(false)
    expect(resolve('system')).toBe('light')
    expect(resolve('dark')).toBe('dark')
  })

  it('le choix est appliqué à <html>, mémorisé, et restauré au démarrage', () => {
    mockSystem(false)
    setTheme('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(window.localStorage.getItem('lasthop-theme')).toBe('dark')
    theme.mode = 'system'
    initTheme()
    expect(theme.mode).toBe('dark')
    setTheme('system')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light') // système clair
  })

  it('valeur mémorisée invalide ou stockage hostile : retour au thème système', () => {
    mockSystem(false)
    window.localStorage.setItem('lasthop-theme', '<script>alert(1)</script>')
    initTheme()
    expect(theme.mode).toBe('system')
    setTheme('evil')
    expect(theme.mode).toBe('system')
  })

  it('en mode système, un changement du système est suivi en direct', () => {
    const listeners = mockSystem(false)
    setTheme('system')
    initTheme()
    expect(theme.resolved).toBe('light')
    mockSystem(true) // le système passe en sombre
    listeners.forEach((fn) => fn())
    expect(theme.resolved).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('le menu propose les trois modes et applique le choix', async () => {
    mockSystem(false)
    setTheme('light')
    const w = mount(ThemeMenu, { attachTo: document.body })
    await w.find('button[aria-label="Choisir le thème"]').trigger('click')
    const items = w.findAll('[role="menuitemradio"]')
    expect(items.map((i) => i.text())).toEqual(['Clair', 'Sombre', 'Système'])
    expect(items[0].attributes('aria-checked')).toBe('true')
    await items[1].trigger('click')
    await flush()
    expect(theme.mode).toBe('dark')
    expect(w.find('[role="menu"]').exists()).toBe(false) // le menu se referme
    w.unmount()
  })

  it('le graphe de topologie a une palette pour chaque thème', () => {
    const colorOf = (mode) => styleFor(mode)[0].style.color
    expect(colorOf('light')).not.toBe(colorOf('dark'))
    expect(styleFor('inconnu')[0].style.color).toBe(colorOf('light'))
  })
})
