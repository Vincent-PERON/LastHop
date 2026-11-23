<script setup>
import { reactive, computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Icon from '../components/Icon.vue'
import Badge from '../components/Badge.vue'
import StatusDot from '../components/StatusDot.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get } from '../api/client.js'
import { can } from '../stores/session.js'
import { dt, RUN_STATUS } from '../utils/format.js'

const d = reactive({ devices: [], endpoints: null, runs: [], error: '', loaded: false })

const reachable = (x) => x.last_topology_status === 'ok' || x.last_poll_status === 'ok'
const kpi = computed(() => ({
  total: d.devices.length,
  ok: d.devices.filter(reachable).length,
  up: d.devices.reduce((n, x) => n + (x.ports_up || 0), 0),
  down: d.devices.reduce((n, x) => n + (x.ports_down || 0), 0),
}))
// Équipements à surveiller : collecte en échec ou jamais réussie
const alerts = computed(() =>
  d.devices
    .filter((x) => [x.last_topology_status, x.last_learning_status, x.last_poll_status].some((s) => s && s !== 'ok'))
    .slice(0, 8),
)

onMounted(async () => {
  try {
    d.devices = await get('/api/v1/devices')
    if (can('search')) d.endpoints = (await get('/api/v1/endpoints', { active: 'true', limit: 1 })).total
    if (can('backups:read')) d.runs = (await get('/api/v1/backups/runs', { limit: 6 })).items
  } catch (e) {
    d.error = e.message
  } finally {
    d.loaded = true
  }
})
</script>

<template>
  <div>
    <PageHeader
      title="Tableau de bord"
      :crumbs="[{ label: 'LastHop' }]"
      :kpis="[{ value: kpi.up, label: 'Ports up' }, { value: kpi.down, label: 'Ports down' }]"
    />
    <section class="content">
      <ErrorBanner :message="d.error" />
      <div class="stat-row">
        <div class="stat"><span class="ico"><Icon name="server" :size="22" /></span><div><b>{{ kpi.total }}</b><span>Équipements</span></div></div>
        <div class="stat okbox"><span class="ico"><Icon name="ok" :size="22" /></span><div><b>{{ kpi.ok }}</b><span>Joignables</span></div></div>
        <div :class="['stat', kpi.total - kpi.ok ? 'badbox' : '']"><span class="ico"><Icon name="alert" :size="22" /></span><div><b>{{ kpi.total - kpi.ok }}</b><span>À vérifier</span></div></div>
        <div v-if="d.endpoints !== null" class="stat"><span class="ico"><Icon name="search" :size="22" /></span><div><b>{{ d.endpoints }}</b><span>Endpoints actifs</span></div></div>
      </div>

      <div class="cols">
        <div class="card">
          <h2>Équipements à surveiller</h2>
          <p v-if="d.loaded && !alerts.length" class="notice"><Icon name="ok" :size="16" /> Toutes les collectes récentes ont réussi.</p>
          <table v-else>
            <thead><tr><th scope="col"></th><th scope="col">Équipement</th><th scope="col">Dernier problème</th></tr></thead>
            <tbody>
              <tr v-for="x in alerts" :key="x.id">
                <td><StatusDot state="bad" label="en alerte" /></td>
                <td><RouterLink :to="{ name: 'device', params: { id: x.id } }">{{ x.name }}</RouterLink> <small class="hint">{{ x.mgmt_ip }}</small></td>
                <td>{{ [x.last_topology_status, x.last_learning_status, x.last_poll_status].find((s) => s && s !== 'ok') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="can('backups:read')" class="card">
          <h2>Dernières sauvegardes</h2>
          <p v-if="d.loaded && !d.runs.length" class="hint">Aucune sauvegarde pour le moment.</p>
          <ul class="timeline">
            <li v-for="r in d.runs" :key="r.id">
              <Badge :kind="RUN_STATUS[r.status]?.[1]">{{ RUN_STATUS[r.status]?.[0] }}</Badge>
              <RouterLink :to="{ name: 'backups', query: { device: r.device_id } }">{{ r.device }}</RouterLink>
              <time>{{ dt(r.started_at) }}</time>
              <div class="hint">{{ r.summary }}</div>
            </li>
          </ul>
          <RouterLink to="/backups">Tous les journaux de sauvegarde ›</RouterLink>
        </div>
      </div>
    </section>
  </div>
</template>
