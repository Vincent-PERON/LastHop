<script setup>
import { computed, ref } from 'vue'
import { RouterLink, RouterView, useRouter, useRoute } from 'vue-router'
import Icon from './components/Icon.vue'
import { session, can } from './stores/session.js'
import { post } from './api/client.js'
import { USER_ROLE_LABEL } from './utils/format.js'

const router = useRouter()
const route = useRoute()
// Coque (barre latérale + bandeau) uniquement pour une session ouverte ; page de connexion et changement imposé : plein écran
const showShell = computed(() => Boolean(session.user) && !route.meta?.bare && !session.mustChange)
const q = ref('')

// Navigation latérale : seules les entrées autorisées sont affichées (la vraie autorisation reste côté serveur)
const groups = computed(() =>
  [
    [
      { to: '/dashboard', label: 'Tableau de bord', icon: 'home', ok: can('inventory:read') },
      { to: '/search', label: 'Recherche', icon: 'search', ok: can('search') },
      { to: '/locate', label: 'Localiser', icon: 'target', ok: can('realtime') },
      { to: '/topology', label: 'Topologie', icon: 'network', ok: can('topology:read') },
      { to: '/devices', label: 'Équipements', icon: 'server', ok: can('inventory:read') },
      { to: '/backups', label: 'Sauvegardes', icon: 'backup', ok: can('backups:read') },
    ],
    [
      { to: '/admin/credentials', label: 'Profils SNMP', icon: 'key', ok: can('credentials:write') },
      { to: '/admin/ssh', label: 'Profils SSH', icon: 'key', ok: can('credentials:write') },
      { to: '/admin/discovery', label: 'Découverte', icon: 'list', ok: can('inventory:write') },
      { to: '/admin/auth', label: 'Authentification', icon: 'shield', ok: can('auth:manage') },
      { to: '/admin/settings', label: 'Paramètres', icon: 'gear', ok: can('settings:write') },
      { to: '/admin/audit', label: 'Audit', icon: 'shield', ok: can('audit:read') },
    ],
    [{ to: '/tokens', label: 'Tokens API', icon: 'token', ok: can('tokens:manage') }],
  ]
    .map((g) => g.filter((l) => l.ok))
    .filter((g) => g.length),
)

function quickSearch() {
  const v = q.value.trim()
  if (v) router.push({ name: 'search', query: { q: v } })
  q.value = ''
}

async function logout() {
  try {
    await post('/api/v1/auth/logout')
  } finally {
    window.location.assign('/login')
  }
}
</script>

<template>
  <div v-if="showShell" class="shell">
    <aside class="sidebar" aria-label="Navigation principale">
      <RouterLink to="/" class="logo" aria-label="LastHop — accueil"><span class="mark">L</span></RouterLink>
      <template v-for="(g, i) in groups" :key="i">
        <hr v-if="i" />
        <RouterLink v-for="l in g" :key="l.to" :to="l.to" class="nav-item">
          <Icon :name="l.icon" :size="22" />
          <span>{{ l.label }}</span>
        </RouterLink>
      </template>
    </aside>
    <div class="main">
      <header class="topbar">
        <RouterLink to="/" class="brand"><span class="mark sm">L</span>Last<span>Hop</span></RouterLink>
        <form class="quick" role="search" @submit.prevent="quickSearch">
          <Icon name="search" :size="18" />
          <input v-model="q" type="search" maxlength="100" placeholder="Recherche rapide : IP, MAC, nom d’hôte, port…" aria-label="Recherche rapide" autocomplete="off" />
        </form>
        <span class="who"><Icon name="user" :size="18" /> {{ session.user?.label }} <em>{{ USER_ROLE_LABEL[session.user?.role] || session.user?.role }}</em></span>
        <RouterLink v-if="session.user?.source === 'local'" to="/account/password" class="icon-btn" title="Mon mot de passe" aria-label="Mon mot de passe"><Icon name="key" :size="20" /></RouterLink>
        <button type="button" class="icon-btn" title="Déconnexion" aria-label="Déconnexion" @click="logout"><Icon name="power" :size="20" /></button>
      </header>
      <RouterView />
    </div>
  </div>
  <RouterView v-else />
</template>
