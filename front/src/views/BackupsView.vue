<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import DataTable from '../components/DataTable.vue'
import Pager from '../components/Pager.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get } from '../api/client.js'
import { dt, RUN_STATUS } from '../utils/format.js'

const route = useRoute()
const limit = ref(25)
const runs = reactive({ items: [], total: 0, offset: 0 })
const status = ref('')
const error = ref('')
const detail = ref(null)
let timer = null

const columns = [
  { accessorKey: 'started_at', header: 'Date' },
  { accessorKey: 'device', header: 'Équipement' },
  { accessorKey: 'trigger', header: 'Déclenchement' },
  { accessorKey: 'status', header: 'Résultat' },
  { accessorKey: 'summary', header: 'Ce qui s’est passé' },
]
const ICON = { ok: '✓', info: 'ℹ', warn: '⚠', error: '✗' }
const failedCount = computed(() => runs.items.filter((r) => r.status === 'failed').length)

async function load(offset = 0) {
  error.value = ''
  try {
    const r = await get('/api/v1/backups/runs', { status: status.value || undefined, device_id: route.query.device || undefined, limit: limit.value, offset })
    runs.items = r.items
    runs.total = r.total
    runs.offset = offset
  } catch (e) {
    error.value = e.message
  }
}

async function open(run) {
  clearTimeout(timer)
  try {
    detail.value = await get(`/api/v1/backups/runs/${run.id}`)
    if (detail.value.status === 'running') timer = setTimeout(() => open(run), 2000) // le journal se complète en direct
    else load(runs.offset)
  } catch (e) {
    error.value = e.message
  }
}

onMounted(() => load())
onBeforeUnmount(() => clearTimeout(timer))
watch(status, () => load())
</script>

<template>
  <div>
    <PageHeader title="Sauvegardes de configuration" :crumbs="[{ label: 'LastHop' }]" :kpis="[{ value: runs.total, label: 'Sauvegardes' }]" />
    <section class="content">
    <p class="hint">Chaque sauvegarde (configuration en cours « running » et de démarrage « startup ») garde un journal expliqué en clair.</p>
    <ErrorBanner :message="error" />
    <div class="filters">
      <label>Résultat
        <select v-model="status"><option value="">Tous</option><option value="failed">Échecs</option><option value="partial">Incomplètes</option><option value="success">Réussies</option></select>
      </label>
      <span v-if="failedCount" class="error">{{ failedCount }} échec(s) sur cette page</span>
    </div>
    <DataTable :columns="columns" :data="runs.items" clickable empty="Aucune sauvegarde pour le moment." @row-click="open">
      <template #cell-started_at="{ value }">{{ dt(value) }}</template>
      <template #cell-trigger="{ value }">{{ value === 'scheduled' ? 'planifiée' : 'manuelle' }}</template>
      <template #cell-status="{ value }"><Badge :kind="RUN_STATUS[value]?.[1]">{{ RUN_STATUS[value]?.[0] || value }}</Badge></template>
    </DataTable>
    <Pager :total="runs.total" :offset="runs.offset" :limit="limit" @change="load" @limit="(n) => { limit = n; load(0) }" />

    <article v-if="detail" class="panel run-log" aria-label="Journal de la sauvegarde">
      <h2>{{ detail.device }} — {{ dt(detail.started_at) }}</h2>
      <p>
        <Badge :kind="RUN_STATUS[detail.status]?.[1]">{{ RUN_STATUS[detail.status]?.[0] }}</Badge>
        {{ detail.summary }}
        <RouterLink v-if="detail.device_id" :to="{ name: 'device', params: { id: detail.device_id } }">Voir l’équipement</RouterLink>
      </p>
      <ol class="events">
        <li v-for="(e, i) in detail.events" :key="i" :class="`ev ev-${e.level}`">
          <span class="ico" aria-hidden="true">{{ ICON[e.level] }}</span>
          <time>{{ dt(e.ts) }}</time>
          <div>
            <p class="msg">{{ e.message }}</p>
            <p v-if="e.advice" class="advice"><strong>Que faire :</strong> {{ e.advice }}</p>
            <details v-if="e.detail"><summary>Détail technique</summary><code class="small">{{ e.detail }}</code></details>
          </div>
        </li>
      </ol>
    </article>
    </section>
  </div>
</template>
