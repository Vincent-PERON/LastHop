<script setup>
import { reactive, ref, computed, onMounted } from 'vue'
import { useRouter, RouterLink } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Icon from '../components/Icon.vue'
import StatusDot from '../components/StatusDot.vue'
import PortBar from '../components/PortBar.vue'
import Pager from '../components/Pager.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, post, del } from '../api/client.js'
import { can } from '../stores/session.js'
import { waitJob } from '../utils/jobs.js'
import { dt, ERROR_LABEL, RUN_STATUS } from '../utils/format.js'

const router = useRouter()
const devices = ref([])
const sites = ref([])
const credentials = ref([])
const error = ref('')
const notice = ref('')
const showForm = ref(false)
const filter = ref('')
const limit = ref(10)
const offset = ref(0)
const empty = () => ({ name: '', mgmt_ip: '', role: 'access', site_id: '', credential_id: '', is_l3: false, is_l2: true, snmp_port: 161 })
const form = reactive(empty())
const siteName = ref('')
const admin = () => can('inventory:write')

const DRIVER = { cisco_ios: 'Cisco IOS', comware: 'HPE Comware', aruba_os: 'HPE Aruba', generic: 'Générique' }
const reachable = (d) => d.last_topology_status === 'ok' || d.last_poll_status === 'ok'
const state = (d) => (reachable(d) ? 'ok' : d.last_topology_status || d.last_poll_status ? 'bad' : 'unknown')

const filtered = computed(() => {
  const f = filter.value.trim().toLowerCase()
  return devices.value.filter((d) => !f || [d.name, d.mgmt_ip, d.model, d.vendor, d.sys_name].some((v) => (v || '').toLowerCase().includes(f)))
})
const page = computed(() => filtered.value.slice(offset.value, offset.value + limit.value))
const kpis = computed(() => [
  { value: devices.value.length, label: 'Équipements' },
  { value: devices.value.filter(reachable).length, label: 'Joignables' },
  { value: devices.value.reduce((n, d) => n + (d.ports_up || 0), 0), label: 'Ports up' },
  { value: devices.value.reduce((n, d) => n + (d.ports_down || 0), 0), label: 'Ports down' },
])
const site = (id) => sites.value.find((s) => s.id === id)?.name || '—'

async function load() {
  try {
    devices.value = await get('/api/v1/devices')
    sites.value = await get('/api/v1/sites')
    if (can('credentials:write')) credentials.value = await get('/api/v1/credentials')
  } catch (e) {
    error.value = e.message
  }
}

async function runJob(d, path, label) {
  error.value = ''
  notice.value = `${label} : ${d.name}…`
  try {
    const { job_id: id } = await post(`/api/v1/devices/${d.id}/${path}`)
    const j = await waitJob(id)
    notice.value = j.status === 'done' ? `${label} réussi : ${d.name}.` : `${label} en échec : ${d.name} — ${ERROR_LABEL[j.error_code] || j.error_code}`
    await load()
  } catch (e) {
    notice.value = ''
    error.value = e.message
  }
}

async function create() {
  error.value = ''
  try {
    await post('/api/v1/devices', { ...form, site_id: form.site_id || null, snmp_port: Number(form.snmp_port) })
    Object.assign(form, empty())
    showForm.value = false
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function remove(d) {
  if (!window.confirm(`Supprimer l’équipement « ${d.name} » ? Ses endpoints deviendront inactifs.`)) return
  try {
    await del(`/api/v1/devices/${d.id}`)
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function addSite() {
  try {
    await post('/api/v1/sites', { name: siteName.value })
    siteName.value = ''
    await load()
  } catch (e) {
    error.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <PageHeader title="Équipements réseau" :crumbs="[{ label: 'LastHop' }]" :kpis="kpis" />
    <section class="content">
      <ErrorBanner :message="error" />
      <p v-if="notice" class="notice" role="status">{{ notice }}</p>

      <div class="toolbar">
        <label class="grow"><span class="hint">Rechercher</span>
          <input v-model.trim="filter" type="search" maxlength="100" placeholder="Nom, IP, modèle…" @input="offset = 0" />
        </label>
        <template v-if="admin()">
          <form class="inline" @submit.prevent="addSite">
            <input v-model.trim="siteName" required maxlength="100" placeholder="Nouveau site" aria-label="Nom du nouveau site" />
            <button type="submit" class="ghost">Créer le site</button>
          </form>
          <button type="button" @click="showForm = !showForm">{{ showForm ? 'Fermer' : '＋ Ajouter un équipement' }}</button>
        </template>
      </div>

      <form v-if="showForm" class="card form-grid" @submit.prevent="create">
        <label>Nom<input v-model.trim="form.name" required maxlength="100" /></label>
        <label>IP de management<input v-model.trim="form.mgmt_ip" required maxlength="45" placeholder="10.20.0.11" /></label>
        <label>Rôle
          <select v-model="form.role"><option value="core">cœur</option><option value="distribution">distribution</option><option value="access">accès</option></select>
        </label>
        <label>Site
          <select v-model="form.site_id"><option value="">—</option><option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option></select>
        </label>
        <label>Profil SNMP
          <select v-model="form.credential_id" required><option value="" disabled>Choisir…</option><option v-for="c in credentials" :key="c.id" :value="c.id">{{ c.name }} ({{ c.version }})</option></select>
        </label>
        <label>Port SNMP<input v-model="form.snmp_port" type="number" min="1" max="65535" /></label>
        <label class="check"><input v-model="form.is_l2" type="checkbox" /> Switch (FDB)</label>
        <label class="check"><input v-model="form.is_l3" type="checkbox" /> Routeur (ARP)</label>
        <button type="submit">Créer</button>
      </form>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Nom</th><th scope="col"></th><th scope="col">Libellé</th><th scope="col">Ports</th><th scope="col">Adresse IP</th>
              <th scope="col">Pilote</th><th scope="col">Site</th><th scope="col">Dernière collecte</th><th scope="col">Sauvegarde</th><th scope="col"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in page" :key="d.id" class="clickable" tabindex="0" @click="router.push({ name: 'device', params: { id: d.id } })" @keydown.enter="router.push({ name: 'device', params: { id: d.id } })">
              <td><strong>{{ d.name }}</strong></td>
              <td><StatusDot :state="state(d)" :label="state(d) === 'ok' ? 'joignable' : state(d) === 'bad' ? 'en échec' : 'jamais collecté'" /></td>
              <td>{{ [d.vendor, d.model].filter(Boolean).join(' ') || '—' }}<br /><small class="hint">{{ d.role }}</small></td>
              <td><PortBar v-if="d.ports_total" :up="d.ports_up" :down="d.ports_down" /><span v-else class="hint">—</span></td>
              <td>{{ d.mgmt_ip }}</td>
              <td><span class="pill dark">SNMP{{ d.snmp_version ? ' ' + d.snmp_version : '' }}</span><span class="pill blue">{{ DRIVER[d.driver] || d.driver }}</span></td>
              <td>{{ site(d.site_id) }}</td>
              <td>{{ dt(d.last_topology_at) }}<Badge v-if="d.last_topology_status && d.last_topology_status !== 'ok'" kind="bad">{{ d.last_topology_status }}</Badge></td>
              <td>
                <template v-if="d.last_backup_status">
                  <Badge :kind="RUN_STATUS[d.last_backup_status]?.[1]">{{ RUN_STATUS[d.last_backup_status]?.[0] }}</Badge>
                  <RouterLink v-if="d.last_backup_status !== 'success' && can('backups:read')" :to="{ name: 'backups', query: { device: d.id } }" @click.stop>pourquoi ?</RouterLink>
                </template>
                <span v-else class="hint">jamais</span>
              </td>
              <td @click.stop>
                <span v-if="admin()" class="row-icons">
                  <button type="button" class="link" title="Tester SNMP" aria-label="Tester SNMP" @click="runJob(d, 'test', 'Test SNMP')"><Icon name="play" :size="17" /></button>
                  <button type="button" class="link" title="Collecter la topologie" aria-label="Collecter la topologie" @click="runJob(d, 'topology', 'Topologie')"><Icon name="network" :size="17" /></button>
                  <button type="button" class="link" title="Learning (ARP/FDB)" aria-label="Learning" @click="runJob(d, 'learn', 'Learning')"><Icon name="refresh" :size="17" /></button>
                  <button v-if="can('backups:run')" type="button" class="link" title="Sauvegarder la configuration" aria-label="Sauvegarder" @click="runJob(d, 'backup', 'Sauvegarde')"><Icon name="backup" :size="17" /></button>
                  <button type="button" class="link" title="Supprimer" aria-label="Supprimer" @click="remove(d)"><Icon name="trash" :size="17" /></button>
                </span>
              </td>
            </tr>
            <tr v-if="!page.length"><td class="empty" colspan="10">Aucun équipement.</td></tr>
          </tbody>
        </table>
      </div>
      <Pager :total="filtered.length" :offset="offset" :limit="limit" :sizes="[10, 25, 50, 100]" @change="(o) => (offset = o)" @limit="(n) => { limit = n; offset = 0 }" />
    </section>
  </div>
</template>
