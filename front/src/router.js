import { createRouter, createWebHistory } from 'vue-router'
import { can, session } from './stores/session.js'

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
const LoginView = () => import('./views/LoginView.vue')
const PasswordView = () => import('./views/PasswordView.vue')
const AuthProvidersView = () => import('./views/AuthProvidersView.vue')
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
  { path: '/login', name: 'login', component: LoginView, meta: { public: true, bare: true, title: 'Connexion' } },
  { path: '/account/password', name: 'password', component: PasswordView, meta: { title: 'Mon compte' } },
  { path: '/admin/auth', name: 'auth', component: AuthProvidersView, meta: { perm: 'auth:manage', title: 'Authentification' } },
  { path: '/forbidden', name: 'forbidden', component: Forbidden, meta: { title: 'Accès refusé' } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const ORDER = ['dashboard', 'search', 'locate', 'topology', 'devices']
export function firstAllowed() {
  const r = routes.find((x) => ORDER.includes(x.name) && (!x.meta?.perm || can(x.meta.perm)))
  return r ? r.path : '/account/password'
}

export const router = createRouter({ history: createWebHistory(), routes })

export function permissionGuard(to) {
  document.title = `${to.meta?.title ? to.meta.title + ' — ' : ''}LastHop`
  if (to.meta?.public) {
    // déjà connecté : la page de connexion n'a plus lieu d'être
    return to.name === 'login' && session.user ? { path: firstAllowed() } : true
  }
  if (!session.user) return { name: 'login', query: to.fullPath && to.fullPath !== '/' ? { next: to.fullPath } : {} }
  // mot de passe initial / réinitialisé : rien d'autre n'est accessible tant qu'il n'a pas été changé
  if (session.mustChange && to.name !== 'password') return { name: 'password' }
  const perm = to.meta?.perm
  if (perm && !can(perm)) return { name: 'forbidden' }
  return true
}

router.beforeEach(permissionGuard)
