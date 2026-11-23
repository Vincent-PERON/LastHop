// Serveur d'API FACTICE pour développer/vérifier le front sans backend (jamais livré dans l'image).
// Usage : MOCK_ROLE=admin|operator|viewer node dev/mock-server.mjs   (port 8787)
import http from 'node:http'

const ROLE = process.env.MOCK_ROLE || 'admin'
const PERMS = {
  viewer: ['search', 'topology:read'],
  operator: ['search', 'topology:read', 'realtime', 'export'],
  admin: ['inventory:read', 'inventory:write', 'credentials:write', 'backups:read', 'backups:run', 'tokens:manage', 'auth:manage', 'topology:read', 'search', 'realtime', 'export', 'audit:read', 'settings:write', 'users:read'],
}[ROLE]

const sites = [{ id: 's1', name: 'Siège' }]
const devices = [
  { id: 'd-core', name: 'sw-core-cisco-01', mgmt_ip: '10.20.0.1', ssh_credential_id: 's1', ssh_port: 22, ssh_allow_legacy: false, backup_enabled: true, ssh_host_fingerprint: null, last_backup_at: new Date().toISOString(), last_backup_status: 'failed', site_id: 's1', role: 'core', driver: 'cisco_ios', vendor: 'Cisco', model: 'WS-C2960X-48FPD-L', is_l3: true, is_l2: true, last_topology_at: new Date().toISOString(), last_topology_status: 'ok', last_learning_at: new Date().toISOString(), last_learning_status: 'ok' },
  { id: 'd-dist', name: 'sw-dist-comware-01', mgmt_ip: '10.20.0.2', site_id: 's1', role: 'distribution', driver: 'comware', vendor: 'HPE Comware', model: 'HPE 5130-24G-4SFP+ EI', is_l3: true, is_l2: true, last_topology_at: new Date().toISOString(), last_topology_status: 'ok', last_learning_at: null, last_learning_status: 'DEVICE_UNREACHABLE' },
  { id: 'd-acc', name: 'sw-access-aruba-01', mgmt_ip: '10.20.0.3', ssh_credential_id: 's1', ssh_port: 22, ssh_allow_legacy: false, backup_enabled: true, ssh_host_fingerprint: 'SHA256:bb1MHlSh0TZW7javVtAoNk2aHUDvWZK00bP9g6b/Bcg', last_backup_at: new Date().toISOString(), last_backup_status: 'success', site_id: 's1', role: 'access', driver: 'aruba_os', vendor: 'HPE Aruba', model: 'JL253A', is_l3: false, is_l2: true, last_topology_at: new Date().toISOString(), last_topology_status: 'ok', last_learning_at: new Date().toISOString(), last_learning_status: 'ok' },
]
const PC = { 'd-core': [38, 10], 'd-dist': [20, 4], 'd-acc': [44, 4] }
for (const d of devices) { const [u, w] = PC[d.id]; Object.assign(d, { ports_up: u, ports_down: w, ports_total: u + w, snmp_version: d.id === 'd-core' ? 'v3' : 'v2c', sys_name: d.name, sys_descr: d.model + ' Software, Version 15.2(7)E3', sys_object_id: '1.3.6.1.4.1.9.1.2134', chassis_mac: '00:11:22:33:44:0' + d.id.length }) }
const graph = {
  nodes: devices.map((d) => ({ id: d.id, label: d.name, name: d.name, role: d.role, vendor: d.vendor, model: d.model, managed: true })),
  edges: [
    { id: 'e1', source: 'd-core', target: 'd-dist', source_port: 'Gi1/0/2', target_port: 'GE1/0/2', protocols: ['cdp', 'lldp'] },
    { id: 'e2', source: 'd-dist', target: 'd-acc', source_port: 'GE1/0/1', target_port: '1', protocols: ['lldp'] },
  ],
}
const ports = [
  { id: 'p1', if_index: 1, name: '1', alias: '<script>alert(1)</script>poste-compta', oper_status: 1, role: 'uplink', role_detected: 'uplink', role_override: null, role_reason: 'lldp_neighbor', mac_count: 31, is_trunk: true, neighbors: [{ sysname: 'sw-dist-comware-01', protocol: 'lldp' }] },
  { id: 'p2', if_index: 2, name: '2', alias: '', oper_status: 1, role: 'access', role_detected: 'access', role_override: null, role_reason: 'none', mac_count: 1, is_trunk: false, neighbors: [{ sysname: 'phone-1001', protocol: 'lldp' }] },
  { id: 'p3', if_index: 3, name: '3', alias: '', oper_status: 2, role: 'access', role_detected: 'uplink', role_override: 'access', role_reason: 'mac_count', mac_count: 25, is_trunk: false, neighbors: [] },
]
const mk = (i, over = {}) => ({ id: `ep${i}`, mac: `02:bb:00:00:00:${String(i).padStart(2, '0')}`, ip: `10.50.0.${10 + i}`, vlan: i % 2 ? 10 : null, vendor: i % 3 ? 'Bravo Devices <b>Inc</b>' : null, hostname: i % 2 ? `pc-${i}.corp.local` : null, device_id: 'd-acc', device: 'sw-access-aruba-01', port: String((i % 4) + 1), first_seen: '2026-11-01T08:00:00Z', last_seen: new Date(Date.now() - i * 60000).toISOString(), active: i % 5 !== 0, ...over })
const endpoints = Array.from({ length: 63 }, (_, i) => mk(i + 1))
const tokens = []
const ev = (level, message, extra = {}) => ({ ts: new Date().toISOString(), level, message, advice: null, detail: null, ...extra })
const RUNS = {
  r1: { id: 'r1', device_id: 'd-core', device: 'sw-core-cisco-01', trigger: 'manual', requested_by: 'demo.admin@example.org', status: 'failed', error_code: 'SSH_AUTH_FAILED', summary: "Sauvegarde échouée : L'équipement a refusé l'identifiant ou le mot de passe (ou la clé) du profil SSH.", results: {}, started_at: new Date(Date.now() - 600000).toISOString(), finished_at: new Date().toISOString(),
    events: [ev('info', 'Début de la sauvegarde de « sw-core-cisco-01 » (10.20.0.1, port SSH 22), demandée par demo.admin@example.org.'), ev('info', 'Connexion SSH à 10.20.0.1:22 avec le profil « backup-ro » (utilisateur backup).'),
      ev('error', "L'équipement a refusé l'identifiant ou le mot de passe (ou la clé) du profil SSH.", { advice: "Vérifiez le profil SSH (utilisateur, mot de passe ou clé) et que ce compte existe sur l'équipement et peut se connecter en SSH.", detail: 'PermissionDenied: Permission denied <script>alert(1)</script>' }),
      ev('error', "Sauvegarde échouée : L'équipement a refusé l'identifiant ou le mot de passe (ou la clé) du profil SSH.")] },
  r2: { id: 'r2', device_id: 'd-acc', device: 'sw-access-aruba-01', trigger: 'scheduled', requested_by: null, status: 'success', error_code: null, summary: 'Sauvegarde réussie : nouvelle version de running.', results: { running: 'success', startup: 'unchanged' }, started_at: new Date(Date.now() - 3600000).toISOString(), finished_at: new Date().toISOString(),
    events: [ev('info', 'Début de la sauvegarde de « sw-access-aruba-01 » (10.20.0.3, port SSH 22) (planifiée).'), ev('ok', 'Connexion SSH établie : l\'empreinte de l\'équipement correspond à celle approuvée, authentification réussie.'), ev('ok', 'La configuration en cours (running) a changé depuis la sauvegarde du 21/11/2026 à 03:00 (4 ligne(s) ajoutée(s), 1 supprimée(s)). Nouvelle version enregistrée (12.4 Ko).'),
      ev('ok', 'La configuration de démarrage (startup) est identique à celle du 21/11/2026 à 03:00 : aucune nouvelle version enregistrée.'),
      ev('warn', 'La configuration en cours (running) est DIFFÉRENTE de la configuration de démarrage (startup) : des modifications n\'ont pas été enregistrées sur l\'équipement et seraient perdues au prochain redémarrage.', { advice: 'Si ces modifications sont voulues, enregistrez-les sur l\'équipement (Aruba : write memory).' }), ev('ok', 'Sauvegarde réussie : nouvelle version de running.')] },
}
const versions = [
  { id: 'b2', kind: 'running', status: 'success', size_bytes: 12700, sha256: 'x', created_at: new Date().toISOString(), run_id: 'r2' },
  { id: 'b3', kind: 'startup', status: 'unchanged', size_bytes: 12500, sha256: 'y', created_at: new Date().toISOString(), run_id: 'r2' },
  { id: 'b1', kind: 'running', status: 'success', size_bytes: 12500, sha256: 'z', created_at: '2026-11-21T03:00:00Z', run_id: 'r0' },
]
const CONFIG = 'hostname sw-core\nenable secret 5 ********\nsnmp-server community ******** RO\ninterface Gi1/0/1\n description <b>uplink</b>\n!\nend'

const send = (res, code, body, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers })
  res.end(body === undefined ? '' : JSON.stringify(body))
}
const sse = (res, id, type, data) => res.write(`id: ${id}\nevent: ${type}\ndata: ${JSON.stringify(data)}\n\n`)
const readBody = (req) => new Promise((r) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => r(b ? JSON.parse(b) : {})) })
const jobs = new Map()

function scenario(query) {
  const base = [
    ['started', { query, kind: /[:.-]/.test(query) && !/^\d+\./.test(query) ? 'mac' : 'ip', timeout_s: 30 }],
    ...(/^\d+\./.test(query) ? [['arp_resolving', { gateways: ['sw-dist-comware-01', 'sw-core-cisco-01'] }]] : []),
  ]
  if (query === '10.99.9.9') return [...base, ['device_queried', { device: 'sw-dist-comware-01', status: 'not_found' }], ['device_queried', { device: 'sw-core-cisco-01', status: 'not_found' }],
    ['failed', { ok: false, error_code: 'IP_NOT_IN_ARP', message: "L'IP n'apparaît dans l'ARP d'aucune passerelle gérée (entrée expirée ou hôte silencieux). Passerelles interrogées : sw-dist-comware-01, sw-core-cisco-01." }], ['done', { ok: false }]]
  const mac = '02:bb:00:00:00:01'
  return [...base, ...(/^\d+\./.test(query) ? [['arp_resolved', { mac, gateway: 'sw-dist-comware-01' }]] : []),
    ['fdb_querying', { switches: devices.map((d) => d.name) }],
    ['device_queried', { device: 'sw-access-aruba-01', status: 'found', port: '4', role: 'access' }],
    ['device_queried', { device: 'sw-dist-comware-01', status: 'found', port: 'GE1/0/1', role: 'uplink' }],
    ['device_queried', { device: 'sw-core-cisco-01', status: 'error', code: 'DEVICE_UNREACHABLE' }],
    ['hop', { depth: 1, device: 'sw-dist-comware-01', port: 'GE1/0/1', role: 'uplink' }],
    ['hop', { depth: 0, device: 'sw-access-aruba-01', port: '4', role: 'access' }],
    ['located', { ok: true, mac, ip: '10.50.0.11', kind: 'mac', elapsed_ms: 1840, vendor: 'Bravo Devices', hostname: 'pc-compta.corp.local', first_seen: '2026-11-01T08:00:00Z', last_seen: new Date().toISOString(), known_ips: ['10.50.0.11'], location: { device: 'sw-access-aruba-01', port: '4', vlan: 10 }, chain: [{ depth: 1, device: 'sw-dist-comware-01', port: 'GE1/0/1', vlan: 10 }], warnings: [{ code: 'PARTIAL_FAILURE', message: 'Certains équipements n’ont pas répondu.' }] }],
    ['done', { ok: true }]]
}

let loggedIn = process.env.MOCK_LOGGED === '1'
let mustChange = process.env.MOCK_MUST_CHANGE === '1'
let totpEnabled = process.env.MOCK_TOTP === '1' // code valide en démo : 123456
let m0
const authProviders = [
  { id: 'ap1', kind: 'oidc', preset: 'keycloak', name: 'Keycloak', enabled: true, config: { issuer: 'https://keycloak.example.org/realms/lasthop', client_id: 'lasthop', scopes: 'openid profile email', groups_claim: 'groups', allowed_domains: [], require_email_verified: false, required_acr: null }, has_secret: true, role_map: { 'lasthop-operators': 'operator' }, default_role: 'viewer', redirect_uri: 'http://127.0.0.1:5173/api/v1/auth/oidc/callback' },
  { id: 'ap2', kind: 'ldap', preset: 'ad', name: 'Active Directory', enabled: true, config: { url: 'ldaps://ad.corp.example:636', starttls: false, insecure: false, ca_pem: null, bind_dn: 'CN=svc,DC=corp,DC=example', bind_dn_template: null, user_base: 'DC=corp,DC=example', user_filter: '(sAMAccountName={username})', uid_attr: 'objectGUID', display_attr: 'displayName', mail_attr: 'mail', group_attr: 'memberOf', group_base: null, group_filter: '(member={user_dn})' }, has_secret: true, role_map: { 'CN=NetOps,OU=Groups,DC=corp,DC=example': 'operator' }, default_role: null, redirect_uri: null },
]
async function readJson(req) {
  let raw = ''
  for await (const chunk of req) raw += chunk
  try { return JSON.parse(raw || '{}') } catch { return {} }
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')
  const p = url.pathname
  const q = url.searchParams
  // --- authentification factice : démarre déconnecté (MOCK_LOGGED=1 pour démarrer connecté ; MOCK_MUST_CHANGE=1 : mot de passe à changer)
  if (p === '/api/v1/auth/providers') return send(res, 200, { local: true, providers: authProviders.filter((x) => x.enabled).map(({ id, name, kind, preset }) => ({ id, name, kind, preset })) })
  if (p === '/api/v1/auth/local/login' && req.method === 'POST') {
    const b = await readJson(req)
    if (b.password !== 'demo-password-1') return send(res, 401, { detail: 'Authentification refusée' })
    if (totpEnabled) return send(res, 200, { status: 'totp_required', challenge: 'mock-challenge-token-0123456789' })
    loggedIn = true
    return send(res, 200, { status: 'ok', must_change_password: mustChange })
  }
  if (p === '/api/v1/auth/local/totp' && req.method === 'POST') {
    const b = await readJson(req)
    if (!['123456', 'ABCDE-FGHJK'].includes((b.code || '').toUpperCase())) return send(res, 401, { detail: 'Authentification refusée' })
    loggedIn = true
    return send(res, 200, { status: 'ok', must_change_password: mustChange })
  }
  if (p === '/api/v1/auth/totp/setup' && req.method === 'POST') {
    const b = await readJson(req)
    if (b.password !== 'demo-password-1') return send(res, 403, { detail: 'Mot de passe incorrect' })
    const svg = "<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120'><rect width='120' height='120' fill='white'/><path d='M10 10h30v30H10zM80 10h30v30H80zM10 80h30v30H10zM50 50h20v20H50z' fill='#02213d'/></svg>"
    return send(res, 200, { secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', uri: 'otpauth://totp/LastHop:admin?secret=JBSWY3DPEHPK3PXP', qr: `data:image/svg+xml;utf8,${encodeURIComponent(svg)}` })
  }
  if (p === '/api/v1/auth/totp/enable' && req.method === 'POST') {
    const b = await readJson(req)
    if (b.code !== '123456') return send(res, 422, { detail: "Code incorrect : vérifiez l'heure de votre appareil et réessayez" })
    totpEnabled = true
    return send(res, 200, { enabled: true, recovery_codes: Array.from({ length: 10 }, (_, i) => `ABCD${i}-EFGH${i}`) })
  }
  if (p === '/api/v1/auth/totp/disable' && req.method === 'POST') { totpEnabled = false; return send(res, 200, { enabled: false }) }
  if (p === '/api/v1/auth/totp/recovery-codes' && req.method === 'POST') return send(res, 200, { recovery_codes: Array.from({ length: 10 }, (_, i) => `WXYZ${i}-JKLM${i}`) })
  if (p.match(/^\/api\/v1\/auth\/ldap\/[\w-]+\/login$/) && req.method === 'POST') {
    const b = await readJson(req)
    if (b.password !== 'demo-password-1') return send(res, 401, { detail: 'Authentification refusée' })
    loggedIn = true
    return send(res, 200, { status: 'ok', role: 'viewer' })
  }
  if (p === '/api/v1/auth/password' && req.method === 'POST') {
    const b = await readJson(req)
    if (b.current_password !== 'demo-password-1') return send(res, 403, { detail: 'Mot de passe actuel incorrect' })
    if ((b.new_password || '').length < 12) return send(res, 422, { detail: 'Le mot de passe doit contenir entre 12 et 128 caractères.' })
    mustChange = false
    return send(res, 200, { status: 'ok', csrf_token: 'mock-csrf-2' })
  }
  if (p === '/api/v1/auth/me') return loggedIn ? send(res, 200, { user_id: 'u1', label: `demo.${ROLE}@example.org`, role: ROLE, permissions: PERMS, csrf_token: 'mock-csrf', auth_source: ROLE === 'admin' ? 'local' : 'oidc', must_change_password: mustChange, totp_enabled: totpEnabled }) : send(res, 401, { detail: 'Authentification requise' })
  if (p === '/api/v1/auth/logout') { loggedIn = false; return send(res, 200, { status: 'logged_out' }) }
  if (p === '/api/v1/auth-providers' && req.method === 'GET') return send(res, 200, authProviders)
  if (p === '/api/v1/auth-providers' && req.method === 'POST') {
    const b = await readJson(req)
    const row = { id: `ap${authProviders.length + 1}`, kind: b.kind, preset: b.preset, name: b.name, enabled: Boolean(b.enabled), config: b.config, has_secret: Boolean(b.secret), role_map: b.role_map || {}, default_role: b.default_role || null, redirect_uri: b.kind === 'oidc' ? 'http://127.0.0.1:5173/api/v1/auth/oidc/callback' : null }
    authProviders.push(row)
    return send(res, 201, row)
  }
  if ((m0 = p.match(/^\/api\/v1\/auth-providers\/([\w-]+)(\/test)?$/))) {
    const row = authProviders.find((x) => x.id === m0[1])
    if (!row) return send(res, 404, { detail: 'Introuvable' })
    if (m0[2]) return send(res, 200, { ok: row.kind === 'oidc', message: row.kind === 'oidc' ? 'Découverte OIDC réussie (démo) ; clés de signature récupérées.' : 'Annuaire injoignable, ou négociation TLS impossible (démo).' })
    if (req.method === 'DELETE') { authProviders.splice(authProviders.indexOf(row), 1); res.writeHead(204); return res.end() }
    if (req.method === 'PUT') { const b = await readJson(req); Object.assign(row, { ...(b.name ? { name: b.name } : {}), ...(b.enabled !== undefined ? { enabled: b.enabled } : {}), ...(b.config ? { config: b.config } : {}), ...(b.role_map ? { role_map: b.role_map } : {}), has_secret: row.has_secret || Boolean(b.secret) }); return send(res, 200, row) }
  }
  if (p === '/api/v1/sites') return send(res, 200, sites)
  if (p === '/api/v1/devices' && req.method === 'GET') return send(res, 200, devices)
  let m
  if ((m = p.match(/^\/api\/v1\/devices\/([\w-]+)$/))) return send(res, 200, devices.find((d) => d.id === m[1]) || devices[2])
  if (p.match(/^\/api\/v1\/devices\/[\w-]+\/interfaces$/)) return send(res, 200, Array.from({ length: 32 }, (_, i) => (i < 3 ? ports[i] : { id: `px${i}`, if_index: i + 1, name: `Gi1/0/${i + 1}`, alias: i % 5 === 0 ? 'poste-compta' : '', oper_status: i % 7 === 0 ? 2 : 1, role: i % 11 === 0 ? 'uplink' : 'access', role_detected: 'access', role_override: null, role_reason: 'none', mac_count: i % 4, neighbors: i % 11 === 0 ? [{ sysname: 'sw-dist-comware-01', port: 'GE1/0/' + i, protocol: 'lldp' }] : [] })))
  if ((m = p.match(/^\/api\/v1\/devices\/([\w-]+)\/(test|topology|learn)$/))) { jobs.set('j1', { id: 'j1', status: 'done', result: {} }); return send(res, 202, { job_id: 'j1' }) }
  if ((m = p.match(/^\/api\/v1\/interfaces\/([\w-]+)\/role$/))) return send(res, 200, { id: m[1] })
  if (p === '/api/v1/topology/graph') return send(res, 200, q.get('include_unmanaged') === 'true' ? { nodes: [...graph.nodes, { id: 'ext:phone', label: 'phone-1001', managed: false }], edges: [...graph.edges, { id: 'e3', source: 'd-acc', target: 'ext:phone', source_port: '2', target_port: null, protocols: ['lldp'] }] } : graph)
  if (p === '/api/v1/endpoints/export.csv') { res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="endpoints.csv"' }); return res.end('mac,ip\r\n') }
  if (p === '/api/v1/endpoints') {
    const needle = (q.get('q') || q.get('hostname') || q.get('mac') || '').toLowerCase()
    let items = endpoints.filter((e) => !needle || JSON.stringify(e).toLowerCase().includes(needle))
    if (q.get('port')) items = items.filter((e) => e.port === q.get('port'))
    if (q.get('interface_id')) items = items.slice(0, 4)
    const off = Number(q.get('offset') || 0), lim = Number(q.get('limit') || 50)
    return send(res, 200, { total: items.length, items: items.slice(off, off + lim) })
  }
  if (p.match(/^\/api\/v1\/endpoints\/[\w-]+\/history$/)) return send(res, 200, [{ ts: new Date().toISOString(), change: 'moved', old: { device: 'sw-access-aruba-01', port: '2' }, new: { device: 'sw-access-aruba-01', port: '4' } }, { ts: '2026-11-01T08:00:00Z', change: 'appeared', old: null, new: { device: 'sw-access-aruba-01', port: '2' } }])
  if (p === '/api/v1/backups/runs') { const st = q.get('status'); let items = Object.values(RUNS).map(({ events, ...r }) => r); if (st) items = items.filter((r) => r.status === st); if (q.get('device_id')) items = items.filter((r) => r.device_id === q.get('device_id')); return send(res, 200, { total: items.length, items }) }
  if ((m = p.match(/^\/api\/v1\/backups\/runs\/([\w-]+)$/))) return send(res, RUNS[m[1]] ? 200 : 404, RUNS[m[1]] || {})
  if (p === '/api/v1/backups/diff') return send(res, 200, { added: 2, removed: 1, diff: '--- running 2026-11-21\n+++ running 2026-11-22\n hostname sw-core\n- description uplink\n+ description uplink-v2\n+ interface Vlan99' })
  if ((m = p.match(/^\/api\/v1\/backups\/(b\d)$/))) return send(res, 200, { ...versions.find((v) => v.id === m[1]), masked: q.get('raw') !== 'true', content: q.get('raw') === 'true' ? CONFIG.replace(/\*{8}/g, 'REALSECRET') : CONFIG })
  if (p.match(/^\/api\/v1\/devices\/[\w-]+\/backups$/)) return send(res, 200, versions)
  if (p === '/api/v1/ssh-credentials') return send(res, 200, [{ id: 's1', name: 'backup-ro', username: 'backup', auth_type: 'password', devices_using: 2 }])
  if (p.match(/^\/api\/v1\/devices\/[\w-]+\/ssh\/hostkey$/)) { jobs.set('hk', { id: 'hk', status: 'done', result: { fingerprint: 'SHA256:bb1MHlSh0TZW7javVtAoNk2aHUDvWZK00bP9g6b/Bcg' } }); return send(res, 202, { job_id: 'hk' }) }
  if (p.match(/^\/api\/v1\/devices\/[\w-]+\/ssh\/trust$/)) return send(res, 200, { trusted: 'ok' })
  if (p.match(/^\/api\/v1\/devices\/[\w-]+\/backup$/)) { jobs.set('bk', { id: 'bk', status: 'failed', error_code: 'SSH_AUTH_FAILED', result: {} }); return send(res, 202, { job_id: 'bk' }) }
  if ((m = p.match(/^\/api\/v1\/jobs\/([\w-]+)$/))) return send(res, 200, typeof jobs.get(m[1]) === 'object' ? jobs.get(m[1]) : { id: m[1], status: 'done', result: {} })
  if (p === '/api/v1/tokens' && req.method === 'GET') return send(res, 200, tokens)
  if (p === '/api/v1/tokens' && req.method === 'POST') { const b = await readBody(req); const t = { id: `t${tokens.length}`, name: b.name, prefix: 'deadbeef', scopes: b.scopes, expires_at: new Date(Date.now() + 90 * 864e5).toISOString(), revoked_at: null, last_used_at: null }; tokens.push(t); return send(res, 201, { ...t, token: 'lasthop_deadbeef.MOCK-ONLY-NOT-A-REAL-TOKEN-0123456789abcdef' }) }
  if (p === '/api/v1/credentials') return send(res, 200, [{ id: 'c1', name: 'lab-v3', version: 'v3', auth_proto: 'sha256', priv_proto: 'aes128', devices_using: 3 }])
  if (p === '/api/v1/settings') return send(res, 200, { snmp_v2c_enabled: false, snmp_allowed_cidrs: ['10.20.0.0/16'], uplink_mac_threshold: 20, trunk_min_tagged_vlans: 2, topology_interval_s: 3600, retention_days: 90, snmp_max_concurrency: 20, realtime_timeout_s: 30 })
  if (p === '/api/v1/audit/verify') return send(res, 200, { intact: true, first_broken_id: null })
  if (p === '/api/v1/audit') return send(res, 200, [{ id: 3, ts: new Date().toISOString(), actor_label: 'demo.admin@example.org', action: 'realtime.search', outcome: 'success', target_type: 'job', source_ip: '10.0.0.9', details: { query: '10.50.0.30' } }, { id: 2, ts: new Date().toISOString(), actor_label: 'demo.admin@example.org', action: 'authz.denied', outcome: 'denied', target_type: null, source_ip: '10.0.0.9', details: {} }])
  if (p === '/api/v1/realtime' && req.method === 'POST') { const b = await readBody(req); const id = `rt${Date.now()}`; jobs.set(id, b.query); return send(res, 202, { job_id: id, events_url: `/api/v1/realtime/${id}/events` }) }
  if ((m = p.match(/^\/api\/v1\/realtime\/([\w-]+)\/events$/))) {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' })
    res.write(': connected\n\n')
    const events = scenario(jobs.get(m[1]) || 'aa:bb:cc:dd:ee:ff')
    let i = 0
    const t = setInterval(() => { if (i >= events.length) { clearInterval(t); return res.end() } sse(res, `${Date.now()}-${i}`, ...events[i++]) }, 600)
    req.on('close', () => clearInterval(t))
    return
  }
  send(res, 404, { detail: 'Introuvable' })
}).listen(8787, '127.0.0.1', () => console.log(`mock API (${ROLE}) sur http://127.0.0.1:8787`))
