<script setup>
import { computed, ref, onMounted, onBeforeUnmount, watch } from 'vue'
import { RouterLink, RouterView, useRouter, useRoute } from 'vue-router'
import Icon from './components/Icon.vue'
import Dropdown from './components/Dropdown.vue'
import ThemeMenu from './components/ThemeMenu.vue'
import { session, can } from './stores/session.js'
import { post } from './api/client.js'
import { USER_ROLE_LABEL } from './utils/format.js'

const router = useRouter()
const route = useRoute()
const q = ref('')
const search = ref(null)
const collapsed = ref(false) // barre latérale réduite (grand écran)
const drawer = ref(false) // tiroir (petit écran)
// Coque (barre latérale + bandeau) uniquement pour une session ouverte ; page de connexion et changement imposé : plein écran
const showShell = computed(() => Boolean(session.user) && !route.meta?.bare && !session.mustChange)

// Navigation latérale : seules les entrées autorisées sont affichées (la vraie autorisation reste côté serveur)
const groups = computed(() =>
  [
    {
      title: 'Menu',
      items: [
        { to: '/dashboard', label: 'Tableau de bord', icon: 'home', ok: can('inventory:read') },
        { to: '/search', label: 'Recherche', icon: 'search', ok: can('search') },
        { to: '/locate', label: 'Localiser', icon: 'target', ok: can('realtime') },
        { to: '/topology', label: 'Topologie', icon: 'network', ok: can('topology:read') },
        { to: '/devices', label: 'Équipements', icon: 'server', ok: can('inventory:read') },
        { to: '/backups', label: 'Sauvegardes', icon: 'backup', ok: can('backups:read') },
      ],
    },
    {
      title: 'Administration',
      items: [
        { to: '/admin/credentials', label: 'Profils SNMP', icon: 'key', ok: can('credentials:write') },
        { to: '/admin/ssh', label: 'Profils SSH', icon: 'key', ok: can('credentials:write') },
        { to: '/admin/discovery', label: 'Découverte', icon: 'list', ok: can('inventory:write') },
        { to: '/admin/auth', label: 'Authentification', icon: 'shield', ok: can('auth:manage') },
        { to: '/admin/settings', label: 'Paramètres', icon: 'gear', ok: can('settings:write') },
        { to: '/admin/audit', label: 'Audit', icon: 'shield', ok: can('audit:read') },
        { to: '/tokens', label: 'Tokens API', icon: 'token', ok: can('tokens:manage') },
      ],
    },
  ]
    .map((g) => ({ ...g, items: g.items.filter((l) => l.ok) }))
    .filter((g) => g.items.length),
)

function quickSearch() {
  const v = q.value.trim()
  if (v) router.push({ name: 'search', query: { q: v } })
  q.value = ''
}

function toggleMenu() {
  if (window.matchMedia?.('(max-width: 1023px)').matches) drawer.value = !drawer.value
  else collapsed.value = !collapsed.value
}

// Raccourci Ctrl/⌘ + K : focus sur la recherche rapide
function onKey(e) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k' && search.value) {
    e.preventDefault()
    search.value.focus()
  }
}
onMounted(() => document.addEventListener('keydown', onKey))
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))
watch(() => route.fullPath, () => (drawer.value = false))

const initial = computed(() => (session.user?.label || '?').charAt(0))

async function logout() {
  try {
    await post('/api/v1/auth/logout')
  } finally {
    window.location.assign('/login')
  }
}
</script>

<template>
  <div v-if="showShell" :class="['shell', { collapsed, open: drawer }]">
    <aside class="sidebar" aria-label="Navigation principale">
      <RouterLink to="/" class="logo" aria-label="LastHop — accueil"><span class="mark">L</span><span class="logo-text">Last<span>Hop</span></span></RouterLink>
      <nav>
        <template v-for="g in groups" :key="g.title">
          <p class="nav-title">{{ g.title }}</p>
          <RouterLink v-for="l in g.items" :key="l.to" :to="l.to" class="nav-item" :title="l.label">
            <Icon :name="l.icon" :size="20" />
            <span class="nav-label">{{ l.label }}</span>
          </RouterLink>
        </template>
      </nav>
    </aside>
    <div class="scrim" aria-hidden="true" @click="drawer = false"></div>
    <div class="main">
      <header class="topbar">
        <button type="button" class="icon-btn square" :aria-label="drawer || !collapsed ? 'Réduire le menu' : 'Ouvrir le menu'" @click="toggleMenu"><Icon name="menu" :size="20" /></button>
        <RouterLink to="/" class="brand"><span class="mark sm">L</span>Last<span>Hop</span></RouterLink>
        <form class="quick" role="search" @submit.prevent="quickSearch">
          <Icon name="search" :size="18" />
          <input ref="search" v-model="q" type="search" maxlength="100" placeholder="Rechercher une IP, une MAC, un nom d’hôte…" aria-label="Recherche rapide" autocomplete="off" />
          <kbd aria-hidden="true">⌘K</kbd>
        </form>
        <div class="topbar-end">
          <ThemeMenu />
          <Dropdown label="Menu du compte" button-class="user-btn">
            <template #trigger>
              <span class="avatar" aria-hidden="true">{{ initial }}</span>
              <span class="who"><span class="name">{{ session.user?.label }}</span> <em>{{ USER_ROLE_LABEL[session.user?.role] || session.user?.role }}</em></span>
              <Icon name="down" :size="16" />
            </template>
            <div class="dd-head"><b>{{ session.user?.label }}</b><small>{{ USER_ROLE_LABEL[session.user?.role] || session.user?.role }}</small></div>
            <RouterLink v-if="session.user?.source === 'local'" to="/account/password" class="dd-item" role="menuitem"><Icon name="key" :size="18" /> Mon compte</RouterLink>
            <button type="button" class="dd-item" role="menuitem" @click="logout"><Icon name="power" :size="18" /> Déconnexion</button>
          </Dropdown>
        </div>
      </header>
      <RouterView />
    </div>
  </div>
  <RouterView v-else />
</template>
