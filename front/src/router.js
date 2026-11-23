import { createRouter, createWebHistory } from 'vue-router'
import { can } from './stores/session.js'

const DashboardView = () => import('./views/DashboardView.vue')
const SearchView = () => import('./views/SearchView.vue')
const LocateView = () => import('./views/LocateView.vue')
const TopologyView = () => import('./views/TopologyView.vue')
const DevicesView = () => import('./views/DevicesView.vue')
const DeviceView = () => import('./views/DeviceView.vue')
const CredentialsView = () => import('./views/CredentialsView.vue')
const DiscoveryView = () => import('./views/DiscoveryView.vue')
const SettingsView = () => import('./views/SettingsView.vue')
const AuditView = () => import('./views/AuditView.vue')
const BackupsView = () => import('./views/BackupsView.vue')
const SshProfilesView = () => import('./views/SshProfilesView.vue')
const TokensView = () => import('./views/TokensView.vue')
const Forbidden = () => import('./views/ForbiddenView.vue')

// `perm` : permission exigée (la vraie autorisation reste TOUJOURS côté serveur ; ceci n'est qu'un confort d'interface)
export const routes = [
  { path: '/', name: 'home', redirect: () => firstAllowed() },
  { path: '/dashboard', name: 'dashboard', component: DashboardView, meta: { perm: 'inventory:read', title: 'Tableau de bord' } },
  { path: '/search', name: 'search', component: SearchView, meta: { perm: 'search', title: 'Recherche' } },
  { path: '/locate', name: 'locate', component: LocateView, meta: { perm: 'realtime', title: 'Localisation en direct' } },
  { path: '/topology', name: 'topology', component: TopologyView, meta: { perm: 'topology:read', title: 'Topologie' } },
  { path: '/devices', name: 'devices', component: DevicesView, meta: { perm: 'inventory:read', title: 'Équipements' } },
  { path: '/devices/:id', name: 'device', component: DeviceView, meta: { perm: 'inventory:read', title: 'Équipement' } },
  { path: '/admin/credentials', name: 'credentials', component: CredentialsView, meta: { perm: 'credentials:write', title: 'Profils SNMP' } },
  { path: '/admin/discovery', name: 'discovery', component: DiscoveryView, meta: { perm: 'inventory:write', title: 'Découverte' } },
  { path: '/backups', name: 'backups', component: BackupsView, meta: { perm: 'backups:read', title: 'Sauvegardes' } },
  { path: '/admin/ssh', name: 'ssh', component: SshProfilesView, meta: { perm: 'credentials:write', title: 'Profils SSH' } },
  { path: '/admin/settings', name: 'settings', component: SettingsView, meta: { perm: 'settings:write', title: 'Paramètres' } },
  { path: '/admin/audit', name: 'audit', component: AuditView, meta: { perm: 'audit:read', title: 'Journal d’audit' } },
  { path: '/tokens', name: 'tokens', component: TokensView, meta: { perm: 'tokens:manage', title: 'Tokens d’API' } },
  { path: '/forbidden', name: 'forbidden', component: Forbidden, meta: { title: 'Accès refusé' } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const ORDER = ['dashboard', 'search', 'locate', 'topology', 'devices']
export function firstAllowed() {
  const r = routes.find((x) => ORDER.includes(x.name) && (!x.meta?.perm || can(x.meta.perm)))
  return r ? r.path : '/forbidden'
}

export const router = createRouter({ history: createWebHistory(), routes })

export function permissionGuard(to) {
  const perm = to.meta?.perm
  if (perm && !can(perm)) return { name: 'forbidden' }
  document.title = `${to.meta?.title ? to.meta.title + ' — ' : ''}LastHop`
  return true
}

router.beforeEach(permissionGuard)
