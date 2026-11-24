<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import PortGrid from '../components/PortGrid.vue'
import StatusDot from '../components/StatusDot.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import DeviceBackups from '../components/DeviceBackups.vue'
import DeviceDiagnostic from '../components/DeviceDiagnostic.vue'
import PortEndpointsModal from '../components/PortEndpointsModal.vue'
import { get, put } from '../api/client.js'
import { can } from '../stores/session.js'
import { dt, ROLE_LABEL, RUN_STATUS } from '../utils/format.js'

const route = useRoute()
const device = ref(null)
const ports = ref([])
const runs = ref([])
const error = ref('')
const picked = ref('')
const modalPort = ref(null) // port dont on affiche les endpoints (fenêtre modale)
const admin = can('inventory:write')

const tab = computed(() => (typeof route.query.tab === 'string' ? route.query.tab : 'summary'))
const tabs = computed(() =>
  [
    { key: 'summary', label: 'Résumé', ok: true },
    { key: 'ports', label: 'Ports', ok: true },
    { key: 'backups', label: 'Sauvegardes', ok: can('backups:read') },
    { key: 'logs', label: 'Journaux', ok: can('backups:read') },
  ]
    .filter((t) => t.ok)
    .map((t) => ({ label: t.label, active: tab.value === t.key, to: { query: { tab: t.key } } })),
)
const kpis = computed(() => [
  { value: device.value?.ports_up ?? 0, label: 'Ports up' },
  { value: device.value?.ports_down ?? 0, label: 'Ports down' },
])
const rows = computed(() => ports.value)

async function load() {
  try {
    device.value = await get(`/api/v1/devices/${route.params.id}`)
    ports.value = await get(`/api/v1/devices/${route.params.id}/interfaces`)
    if (can('backups:read')) runs.value = (await get('/api/v1/backups/runs', { device_id: route.params.id, limit: 30 })).items
  } catch (e) {
    error.value = e.message
  }
}

async function setRole(p, ev) {
  try {
    await put(`/api/v1/interfaces/${p.id}/role`, { role: ev.target.value || null })
  } catch (e) {
    error.value = e.message
  }
  await load()
}

const select = (p) => {
  picked.value = p.id
  modalPort.value = p
}
onMounted(load)
watch(() => route.params.id, load)
</script>

<template>
  <div>
    <PageHeader
      :title="device ? `${device.name} (${device.mgmt_ip})` : 'Équipement'"
      :crumbs="[{ label: 'LastHop' }, { label: 'Équipements', to: '/devices' }]"
      :kpis="kpis"
      :tabs="tabs"
    />
    <section class="content">
      <ErrorBanner :message="error" />

      <div v-if="device && tab === 'summary'" class="cols">
        <div class="card">
          <h2>Informations SNMP</h2>
          <dl class="info">
            <dt>Nom SNMP</dt><dd>{{ device.sys_name || '—' }}</dd>
            <dt>Description</dt><dd>{{ device.sys_descr || '—' }}</dd>
            <dt>Constructeur</dt><dd>{{ [device.vendor, device.model].filter(Boolean).join(' ') || 'non identifié' }}</dd>
            <dt>Pilote</dt><dd>{{ device.driver }}</dd>
            <dt>Rôle</dt><dd>{{ ROLE_LABEL[device.role] || device.role }}</dd>
            <dt>MAC du châssis</dt><dd><code>{{ device.chassis_mac || '—' }}</code></dd>
            <dt>OID système</dt><dd><code>{{ device.sys_object_id || '—' }}</code></dd>
            <dt>Topologie</dt><dd>{{ dt(device.last_topology_at) }} <Badge v-if="device.last_topology_status" :kind="device.last_topology_status === 'ok' ? 'ok' : 'bad'">{{ device.last_topology_status }}</Badge></dd>
            <dt>Learning</dt><dd>{{ dt(device.last_learning_at) }} <Badge v-if="device.last_learning_status" :kind="device.last_learning_status === 'ok' ? 'ok' : 'bad'">{{ device.last_learning_status }}</Badge></dd>
            <dt v-if="can('backups:read')">Sauvegarde</dt>
            <dd v-if="can('backups:read')">
              <template v-if="device.last_backup_status"><Badge :kind="RUN_STATUS[device.last_backup_status]?.[1]">{{ RUN_STATUS[device.last_backup_status]?.[0] }}</Badge> {{ dt(device.last_backup_at) }}</template>
              <template v-else>jamais</template>
            </dd>
          </dl>
        </div>
        <div class="card">
          <h2>Ports réseau</h2>
          <ul class="legend">
            <li><i class="l-up"></i> up</li><li><i class="l-down"></i> down</li><li><i class="l-uplink"></i> uplink</li>
          </ul>
          <PortGrid :ports="ports" :selected="picked" @select="select" />
          <p class="hint">Cliquez sur un port pour voir ses endpoints.</p>
        </div>
      </div>

      <DeviceDiagnostic v-if="device && tab === 'summary' && admin" :device="device" />

      <div v-if="device && tab === 'ports'" class="card">
        <h2>Ports réseau</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th scope="col">Index</th><th scope="col">État</th><th scope="col">Nom</th><th scope="col">Description</th><th scope="col">Rôle</th><th scope="col">MAC apprises</th><th scope="col">Voisin</th><th scope="col">Port voisin</th><th scope="col"></th></tr></thead>
            <tbody>
              <tr v-for="p in rows" :key="p.id">
                <td>{{ p.if_index }}</td>
                <td><StatusDot :state="p.oper_status === 1 ? 'ok' : 'bad'" :label="p.oper_status === 1 ? 'up' : 'down'" /></td>
                <td><strong>{{ p.name }}</strong></td>
                <td>{{ p.alias || '—' }}</td>
                <td>
                  <Badge :kind="p.role === 'uplink' ? 'warn' : 'ok'">{{ ROLE_LABEL[p.role] }}</Badge>
                  <small v-if="p.role_override" class="hint"> (forcé)</small><small v-else-if="p.role_reason && p.role_reason !== 'none'" class="hint"> · {{ p.role_reason }}</small>
                  <select v-if="admin" class="role-select" :value="p.role_override || ''" :aria-label="`Rôle du port ${p.name}`" @change="setRole(p, $event)">
                    <option value="">auto</option><option value="access">accès</option><option value="uplink">uplink</option>
                  </select>
                </td>
                <td>{{ p.mac_count }}</td>
                <td>{{ p.neighbors.map((n) => n.sysname).filter(Boolean).join(', ') || '—' }}</td>
                <td>{{ p.neighbors.map((n) => n.port).filter(Boolean).join(', ') || '—' }}</td>
                <td><button type="button" class="ghost" :aria-label="`Voir les endpoints du port ${p.name}`" @click="modalPort = p">Endpoints</button></td>
              </tr>
              <tr v-if="!rows.length"><td class="empty" colspan="9">Aucun port : lancez une collecte de topologie.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <DeviceBackups v-if="device && tab === 'backups' && can('backups:read')" :device="device" @changed="load" />

      <div v-if="device && tab === 'logs' && can('backups:read')" class="card">
        <h2>Journaux de sauvegarde</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th scope="col">Date</th><th scope="col">Résultat</th><th scope="col">Ce qui s’est passé</th></tr></thead>
            <tbody>
              <tr v-for="r in runs" :key="r.id">
                <td>{{ dt(r.started_at) }}</td>
                <td><Badge :kind="RUN_STATUS[r.status]?.[1]">{{ RUN_STATUS[r.status]?.[0] }}</Badge></td>
                <td>{{ r.summary }} <RouterLink :to="{ name: 'backups', query: { device: device.id } }">détail</RouterLink></td>
              </tr>
              <tr v-if="!runs.length"><td class="empty" colspan="3">Aucune sauvegarde pour cet équipement.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
    <PortEndpointsModal v-if="modalPort && device" :device="device" :port="modalPort" @close="modalPort = null" />
  </div>
</template>
