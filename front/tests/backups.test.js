import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import BackupsView from '../src/views/BackupsView.vue'
import DeviceBackups from '../src/components/DeviceBackups.vue'
import SshProfilesView from '../src/views/SshProfilesView.vue'
import { login, logout, makeRouter, mockFetch, flush } from './helpers.js'

const ev = (level, message, extra = {}) => ({ ts: '2026-11-22T10:00:00Z', level, message, advice: null, detail: null, ...extra })
const FAILED = {
  id: 'r1', device_id: 'd1', device: 'sw1', trigger: 'manual', status: 'failed', error_code: 'SSH_AUTH_FAILED', summary: 'Sauvegarde échouée : refus.',
  started_at: '2026-11-22T10:00:00Z',
  events: [
    ev('info', 'Début de la sauvegarde de « sw1 ».'),
    ev('error', "L'équipement a refusé l'identifiant ou le mot de passe.", { advice: 'Vérifiez le profil SSH.', detail: '<img src=x onerror=alert(1)>' }),
  ],
}

afterEach(() => { logout(); vi.unstubAllGlobals() })

describe('BackupsView : journal lisible', () => {
  it('liste les sauvegardes et affiche le journal avec « Que faire » et le détail technique replié', async () => {
    login('admin')
    mockFetch((url) => {
      if (url.startsWith('/api/v1/backups/runs/r1')) return FAILED
      return { total: 1, items: [{ ...FAILED, events: undefined }] }
    })
    const router = await makeRouter('/backups')
    const w = mount(BackupsView, { global: { plugins: [router] } })
    await flush()
    expect(w.text()).toContain('1 échec(s) sur cette page')
    expect(w.find('td[data-col="status"]').text()).toBe('échouée')
    await w.find('tbody tr').trigger('click')
    await flush()
    const log = w.find('.run-log')
    expect(log.findAll('li.ev')).toHaveLength(2)
    expect(log.find('.ev-error .msg').text()).toContain('refusé l\'identifiant')
    expect(log.find('.advice').text()).toContain('Que faire : Vérifiez le profil SSH.')
    const details = log.find('details')
    expect(details.attributes('open')).toBeUndefined() // détail technique replié par défaut
    expect(details.text()).toContain('<img src=x onerror=alert(1)>') // texte littéral
    expect(w.find('img').exists()).toBe(false)
  })

  it('actualise le journal tant que la sauvegarde est en cours', async () => {
    login('admin')
    vi.useFakeTimers({ toFake: ['setTimeout'] })
    let calls = 0
    mockFetch((url) => {
      if (url.startsWith('/api/v1/backups/runs/r1')) { calls++; return { ...FAILED, status: calls < 2 ? 'running' : 'success', events: FAILED.events.slice(0, calls) } }
      return { total: 1, items: [{ ...FAILED, status: 'running', events: undefined }] }
    })
    const router = await makeRouter('/backups')
    const w = mount(BackupsView, { global: { plugins: [router] } })
    await vi.advanceTimersByTimeAsync(10)
    await w.find('tbody tr').trigger('click')
    await vi.advanceTimersByTimeAsync(10)
    expect(w.findAll('li.ev')).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(2100)
    expect(w.findAll('li.ev')).toHaveLength(2)
    vi.useRealTimers()
  })
})

describe('DeviceBackups', () => {
  const device = { id: 'd1', name: 'sw1', ssh_credential_id: '', ssh_port: 22, ssh_allow_legacy: false, backup_enabled: false, ssh_host_fingerprint: null }

  async function mountPanel(handler) {
    login('admin')
    const m = mockFetch((url, init) => {
      if (url.startsWith('/api/v1/devices/d1/backups')) return [200, [{ id: 'b1', kind: 'running', status: 'success', size_bytes: 10, created_at: '2026-11-22T10:00:00Z' }, { id: 'b2', kind: 'running', status: 'success', size_bytes: 12, created_at: '2026-11-21T10:00:00Z' }]]
      if (url === '/api/v1/ssh-credentials') return [200, []]
      return handler(url, init)
    })
    const router = await makeRouter('/devices/d1')
    const w = mount(DeviceBackups, { props: { device }, global: { plugins: [router] } })
    await flush()
    return { w, ...m }
  }

  it('avertit qu’aucune sauvegarde n’est tentée sans empreinte approuvée, et exige de la ressaisir', async () => {
    const { w, calls } = await mountPanel((url) => {
      if (url.endsWith('/ssh/hostkey')) return [202, { job_id: 'j1' }]
      if (url === '/api/v1/jobs/j1') return { id: 'j1', status: 'done', result: { fingerprint: 'SHA256:abc123' } }
      return [200, {}]
    })
    expect(w.text()).toContain('aucune sauvegarde ne sera tentée')
    await w.findAll('button').find((b) => b.text().includes('Vérifier l’empreinte')).trigger('click')
    await flush(); await flush()
    expect(w.text()).toContain('SHA256:abc123')
    const approve = w.findAll('button').find((b) => b.text().includes('Approuver'))
    expect(approve.attributes('disabled')).toBeDefined() // pas d'approbation à l'aveugle
    await w.find('input[aria-label="Empreinte à confirmer"]').setValue('SHA256:abc123')
    await approve.trigger('click')
    await flush()
    const post = calls.find((c) => c.url.endsWith('/ssh/trust'))
    expect(JSON.parse(post.init.body)).toEqual({ job_id: 'j1', fingerprint: 'SHA256:abc123' })
    expect(post.init.headers['X-CSRF-Token']).toBe('csrf-123')
  })

  it('contenu : secrets masqués par défaut ; contenu brut seulement après confirmation', async () => {
    const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(true)
    vi.stubGlobal('confirm', confirm)
    window.confirm = confirm
    const { w, calls } = await mountPanel((url) => (url.includes('raw=true') ? { kind: 'running', created_at: '2026-11-22T10:00:00Z', masked: false, content: 'secret REAL' } : { kind: 'running', created_at: '2026-11-22T10:00:00Z', masked: true, content: 'secret ********\n<script>x</script>' }))
    await w.findAll('button').find((b) => b.text() === 'Voir').trigger('click')
    await flush()
    expect(w.find('pre.config').text()).toContain('********')
    expect(w.find('pre.config').text()).toContain('<script>x</script>') // texte, jamais exécuté
    expect(w.find('script').exists()).toBe(false)
    const raw = w.findAll('button').find((b) => b.text() === 'Contenu brut')
    await raw.trigger('click')
    await flush()
    expect(calls.some((c) => c.url.includes('raw=true'))).toBe(false) // refus de la confirmation : aucune requête
    await raw.trigger('click')
    await flush()
    expect(calls.some((c) => c.url.includes('raw=true'))).toBe(true)
    expect(w.text()).toContain('contenu complet')
  })

  it('compare deux versions (2 maximum) et colore les lignes en texte', async () => {
    const { w } = await mountPanel(() => ({ added: 1, removed: 1, diff: '--- a\n+++ b\n-old\n+new <b>x</b>' }))
    const boxes = w.findAll('tbody input[type="checkbox"]')
    await boxes[0].setValue(true)
    await boxes[1].setValue(true)
    await w.findAll('button').find((b) => b.text().includes('Comparer')).trigger('click')
    await flush()
    expect(w.find('pre.config .add').text()).toContain('+new <b>x</b>')
    expect(w.find('pre.config .del').text()).toContain('-old')
    expect(w.find('pre.config b').exists()).toBe(false)
  })

  it('lance une sauvegarde et affiche le résumé en clair', async () => {
    const { w } = await mountPanel((url) => {
      if (url.endsWith('/backup')) return [202, { job_id: 'j2' }]
      if (url === '/api/v1/jobs/j2') return { id: 'j2', status: 'failed', error_code: 'SSH_UNREACHABLE' }
      if (url.startsWith('/api/v1/backups/runs')) return { total: 1, items: [{ status: 'failed', summary: 'Sauvegarde échouée : L’équipement n’a pas répondu.' }] }
      return [200, {}]
    })
    await w.findAll('button').find((b) => b.text().includes('Sauvegarder maintenant')).trigger('click')
    await flush(); await flush()
    expect(w.find('.result.bad').text()).toContain('L’équipement n’a pas répondu')
    expect(w.find('.result.bad a').exists()).toBe(true)
  })
})

describe('SshProfilesView', () => {
  it('saisie du secret en champ masqué, efface le formulaire après envoi, ne réaffiche jamais le secret', async () => {
    login('admin')
    const { calls } = mockFetch((url, init) => (init.method === 'POST' ? [201, { id: 's1' }] : [200, [{ id: 's1', name: 'p', username: 'u', auth_type: 'password', devices_using: 0 }]]))
    const router = await makeRouter('/admin/ssh')
    const w = mount(SshProfilesView, { global: { plugins: [router] } })
    await flush()
    const pw = w.find('input[type="password"]')
    expect(pw.attributes('autocomplete')).toBe('new-password')
    await w.find('input[maxlength="100"]').setValue('p')
    await w.find('input[maxlength="64"]').setValue('u')
    await pw.setValue('S3cret-pass!')
    await w.find('form').trigger('submit')
    await flush(); await flush()
    expect(JSON.parse(calls.find((c) => c.init.method === 'POST').init.body)).toMatchObject({ name: 'p', username: 'u', password: 'S3cret-pass!' })
    expect(w.find('input[type="password"]').element.value).toBe('') // effacé
    expect(w.html()).not.toContain('S3cret-pass!')
  })
})
