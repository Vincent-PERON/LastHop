// Thème d'interface : clair, sombre ou système (suit le réglage du système d'exploitation en direct).
// Seul le choix « light | dark | system » est mémorisé (localStorage) ; il ne contient aucune donnée sensible.
import { reactive } from 'vue'

const KEY = 'lasthop-theme'
export const MODES = ['light', 'dark', 'system']
export const theme = reactive({ mode: 'system', resolved: 'light' })

const query = () => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null)

export function resolve(mode) {
  if (mode === 'light' || mode === 'dark') return mode
  return query()?.matches ? 'dark' : 'light'
}

function apply() {
  theme.resolved = resolve(theme.mode)
  document.documentElement.setAttribute('data-theme', theme.resolved)
  document.documentElement.style.colorScheme = theme.resolved
}

export function setTheme(mode) {
  theme.mode = MODES.includes(mode) ? mode : 'system'
  try {
    window.localStorage.setItem(KEY, theme.mode)
  } catch {
    /* stockage indisponible : le choix vaut pour cette page seulement */
  }
  apply()
}

export function initTheme() {
  let saved = 'system'
  try {
    saved = window.localStorage.getItem(KEY) || 'system'
  } catch {
    /* thème système */
  }
  theme.mode = MODES.includes(saved) ? saved : 'system'
  apply()
  // « Système » : suit les changements du système sans rechargement
  query()?.addEventListener?.('change', () => {
    if (theme.mode === 'system') apply()
  })
}
