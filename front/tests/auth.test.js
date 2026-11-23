import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import LoginView from '../src/views/LoginView.vue'
import PasswordView from '../src/views/PasswordView.vue'
import AuthProvidersView from '../src/views/AuthProvidersView.vue'
import { login, logout, makeRouter, mockFetch, flush, session } from './helpers.js'

afterEach(() => {
  logout()
  vi.restoreAllMocks()
})

const ME = { user_id: 'u1', label: 'admin', role: 'admin', permissions: ['search'], csrf_token: 'c1', auth_source: 'local', must_change_password: false }
const PROVIDERS = { local: true, providers: [
  { id: 'kc', name: 'Keycloak', kind: 'oidc', preset: 'keycloak' },
  { id: 'ad', name: 'Active Directory', kind: 'ldap', preset: 'ad' },
] }

async function mountLogin(handler, path = '/login?next=%2Fsearch%3Fq%3D10.0.0.5') {
  const m = mockFetch(handler)
  const router = await makeRouter(path)
  const w = mount(LoginView, { global: { plugins: [router] } })
  await flush(); await flush()
  return { w, router, ...m }
}

describe('LoginView', () => {
  it('affiche le compte local, les annuaires LDAP et un bouton par fournisseur OIDC', async () => {
    const { w } = await mountLogin(() => PROVIDERS)
    expect(w.text()).toContain('Se connecter avec Keycloak')
    const options = w.findAll('select option').map((o) => o.text())
    expect(options).toEqual(['Compte local (super admin)', 'Active Directory (annuaire)'])
    expect(w.find('input[type="password"]').exists()).toBe(true)
  })

  it('connexion locale : envoie les identifiants au bon endpoint, vide le mot de passe, retourne à la destination', async () => {
    const { w, router, calls } = await mountLogin((url) => {
      if (url.endsWith('/auth/providers')) return PROVIDERS
      if (url.endsWith('/auth/local/login')) return { status: 'ok', must_change_password: false }
      if (url.endsWith('/auth/me')) return ME
    })
    await w.find('input[autocomplete="username"]').setValue('admin')
    await w.find('input[type="password"]').setValue('secret-passphrase-1')
    await w.find('form').trigger('submit')
    await flush(); await flush(); await flush()
    const loginCall = calls.find((c) => c.url.endsWith('/auth/local/login'))
    expect(JSON.parse(loginCall.init.body)).toEqual({ username: 'admin', password: 'secret-passphrase-1' })
    expect(w.find('input[type="password"]').element.value).toBe('')
    expect(session.user.source).toBe('local')
    expect(router.currentRoute.value.fullPath).toBe('/search?q=10.0.0.5')
  })

  it('mot de passe initial : redirige vers le changement imposé', async () => {
    const { w, router } = await mountLogin((url) => {
      if (url.endsWith('/auth/providers')) return PROVIDERS
      if (url.endsWith('/auth/local/login')) return { status: 'ok', must_change_password: true }
      if (url.endsWith('/auth/me')) return { ...ME, must_change_password: true }
    })
    await w.find('input[autocomplete="username"]').setValue('admin')
    await w.find('input[type="password"]').setValue('initial-secret-1')
    await w.find('form').trigger('submit')
    await flush(); await flush(); await flush()
    expect(router.currentRoute.value.name).toBe('password')
  })

  it('LDAP : utilise l’endpoint de l’annuaire choisi ; échec = message générique, pas de redirection', async () => {
    const { w, router, calls } = await mountLogin((url) => {
      if (url.endsWith('/auth/providers')) return PROVIDERS
      if (url.includes('/auth/ldap/')) return [401, { detail: 'ldap_bad_credentials: détail interne' }]
    })
    await w.find('select').setValue('ad')
    await w.find('input[autocomplete="username"]').setValue('alice')
    await w.find('input[type="password"]').setValue('mauvais')
    await w.find('form').trigger('submit')
    await flush(); await flush()
    expect(calls.some((c) => c.url === '/api/v1/auth/ldap/ad/login')).toBe(true)
    expect(w.text()).toContain('Identifiant ou mot de passe incorrect.')
    expect(w.text()).not.toContain('détail interne')
    expect(router.currentRoute.value.name).toBe('login') // pas de boucle de redirection sur 401
    expect(w.find('input[type="password"]').element.value).toBe('')
  })

  it('OIDC : le bouton navigue vers le login du fournisseur avec un chemin de retour interne', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { ...window.location, assign })
    const { w } = await mountLogin(() => PROVIDERS, '/login?next=%2F%2Fevil.example')
    await w.find('button.provider-btn').trigger('click')
    expect(assign).toHaveBeenCalledWith('/api/v1/auth/oidc/kc/login?next=%2F')
    vi.unstubAllGlobals()
  })

  it('aucun stockage navigateur n’est utilisé', async () => {
    const set = vi.spyOn(Storage.prototype, 'setItem')
    await mountLogin(() => PROVIDERS)
    expect(set).not.toHaveBeenCalled()
  })
})

describe('PasswordView', () => {
  it('refuse deux saisies différentes sans appeler le serveur, puis envoie et ouvre la nouvelle session', async () => {
    login('admin')
    const { calls } = mockFetch((url) => {
      if (url.endsWith('/auth/password')) return { status: 'ok', csrf_token: 'c2' }
      if (url.endsWith('/auth/me')) return ME
    })
    const router = await makeRouter('/account/password')
    const w = mount(PasswordView, { global: { plugins: [router] } })
    const [cur, n1, n2] = w.findAll('input')
    await cur.setValue('ancien-secret-1'); await n1.setValue('nouveau-secret-long-1'); await n2.setValue('different-secret-xx')
    await w.find('form').trigger('submit')
    expect(calls).toHaveLength(0)
    expect(w.text()).toContain('ne correspondent pas')
    await n2.setValue('nouveau-secret-long-1')
    await w.find('form').trigger('submit')
    await flush(); await flush(); await flush()
    const body = JSON.parse(calls.find((c) => c.url.endsWith('/auth/password')).init.body)
    expect(body).toEqual({ current_password: 'ancien-secret-1', new_password: 'nouveau-secret-long-1' })
    expect(w.findAll('input').every((i) => i.element.value === '')).toBe(true)
  })
})

const ROWS = [
  { id: 'p1', kind: 'oidc', preset: 'keycloak', name: 'Keycloak', enabled: true, config: { issuer: 'https://kc/realms/x', client_id: 'lasthop', allowed_domains: [] }, has_secret: true, role_map: { ops: 'operator' }, default_role: null, redirect_uri: 'https://lasthop.example.org/api/v1/auth/oidc/callback' },
  { id: 'p2', kind: 'ldap', preset: 'ldap', name: 'Labo LDAP', enabled: false, config: { url: 'ldap://x', insecure: true, starttls: false }, has_secret: true, role_map: {}, default_role: 'viewer', redirect_uri: null },
]

describe('AuthProvidersView', () => {
  async function open(handler) {
    login('admin')
    const m = mockFetch(handler)
    const router = await makeRouter('/admin/auth')
    const w = mount(AuthProvidersView, { global: { plugins: [router] }, attachTo: document.body })
    await flush(); await flush()
    return { w, ...m }
  }

  it('liste les fournisseurs sans jamais afficher de secret et signale la connexion non chiffrée', async () => {
    const { w } = await open(() => ROWS)
    expect(w.text()).toContain('Keycloak')
    expect(w.text()).toContain('connexion non chiffrée')
    expect(w.find('input[type="password"]').exists()).toBe(false) // aucun champ de secret dans la liste
    expect(w.text()).not.toContain('client_secret')
    w.unmount()
  })

  it('création LDAP : l’option « non chiffré » exige la reconnaissance du risque, le secret part une seule fois et est effacé', async () => {
    const { w, calls } = await open((url, init) => (init.method === 'POST' ? [201, { id: 'new' }] : ROWS))
    await w.find('p button').trigger('click')
    await flush()
    const dialog = document.body.querySelector('[role="dialog"]')
    expect(dialog).not.toBeNull()
    // choix « Active Directory », mode non chiffré
    const selects = dialog.querySelectorAll('select')
    selects[0].value = 'ldap'; selects[0].dispatchEvent(new Event('change'))
    await flush()
    const field = (label) => [...dialog.querySelectorAll('label')].find((l) => l.textContent.includes(label))?.querySelector('input,select,textarea')
    const set = async (el, v) => { el.value = v; el.dispatchEvent(new Event('input')); await flush() }
    await set(field('Nom affiché'), 'Labo')
    await set(field('URL'), 'ldap://ldap.lab:389')
    const mode = field('Chiffrement'); mode.value = 'insecure'; mode.dispatchEvent(new Event('change')); await flush()
    await set(field('Base de recherche'), 'dc=lab,dc=local')
    await set(field('Mot de passe du compte de service'), 'Svc-Secret-1')
    dialog.querySelector('form').dispatchEvent(new Event('submit'))
    await flush()
    expect(calls.some((c) => c.init.method === 'POST')).toBe(false) // refusé côté interface tant que le risque n'est pas reconnu
    expect(dialog.textContent).toContain('Cochez la reconnaissance')
    const ack = [...dialog.querySelectorAll('label.check input[type="checkbox"]')].find((c) => c.closest('.warn-box'))
    ack.checked = true; ack.dispatchEvent(new Event('change')); await flush()
    dialog.querySelector('form').dispatchEvent(new Event('submit'))
    await flush(); await flush()
    const post = calls.find((c) => c.init.method === 'POST')
    const body = JSON.parse(post.init.body)
    expect(body).toMatchObject({ kind: 'ldap', preset: 'ldap', name: 'Labo', secret: 'Svc-Secret-1' })
    expect(body.config).toMatchObject({ url: 'ldap://ldap.lab:389', insecure: true, starttls: false })
    expect(body.role_map).toEqual({}) // les lignes vides ne sont pas envoyées
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    w.unmount()
  })

  it('le test d’un fournisseur affiche le message du serveur en texte', async () => {
    const { w } = await open((url, init) => (init.method === 'POST' ? { ok: false, message: '<img src=x onerror=alert(1)> Annuaire injoignable' } : ROWS))
    await w.findAll('button').find((b) => b.text() === 'Tester').trigger('click')
    await flush(); await flush()
    expect(w.find('.test-result').text()).toContain('<img src=x onerror=alert(1)>')
    expect(w.find('.test-result img').exists()).toBe(false)
    w.unmount()
  })
})
