<script setup>
import { reactive, ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import Pager from '../components/Pager.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, qs } from '../api/client.js'
import { can } from '../stores/session.js'
import { dt } from '../utils/format.js'

const route = useRoute()
const router = useRouter()
const limit = ref(25)
const FIELDS = ['q', 'mac', 'ip', 'vlan', 'hostname', 'port', 'device_id', 'active']
const f = reactive({ q: '', mac: '', ip: '', vlan: '', hostname: '', port: '', device_id: '', active: '' })
const state = reactive({ items: [], total: 0, offset: 0, loading: false, error: '' })
const selected = ref(null)
const history = ref([])
const advanced = ref(false)

const columns = [
  { accessorKey: 'mac', header: 'MAC' },
  { accessorKey: 'ip', header: 'IP' },
  { accessorKey: 'hostname', header: 'Nom d’hôte' },
  { accessorKey: 'vendor', header: 'Constructeur' },
  { accessorKey: 'vlan', header: 'VLAN' },
  { accessorKey: 'device', header: 'Switch' },
  { accessorKey: 'port', header: 'Port' },
  { accessorKey: 'last_seen', header: 'Dernière vue' },
  { accessorKey: 'active', header: 'État' },
]

const params = computed(() => Object.fromEntries(FIELDS.filter((k) => f[k] !== '').map((k) => [k, f[k]])))
const exportUrl = computed(() => `/api/v1/endpoints/export.csv${qs(params.value)}`)

async function run(offset = 0) {
  state.loading = true
  state.error = ''
  selected.value = null
  try {
    const r = await get('/api/v1/endpoints', { ...params.value, limit: limit.value, offset })
    state.items = r.items
    state.total = r.total
    state.offset = offset
  } catch (e) {
    state.error = e.message
  } finally {
    state.loading = false
  }
}

function submit() {
  router.replace({ query: params.value }) // l'URL reflète la recherche (partageable)
  run(0)
}

async function open(row) {
  selected.value = row
  history.value = []
  try {
    history.value = await get(`/api/v1/endpoints/${row.id}/history`)
  } catch (e) {
    state.error = e.message
  }
}

function fromRoute() {
  for (const k of FIELDS) f[k] = typeof route.query[k] === 'string' ? route.query[k] : ''
  advanced.value = FIELDS.slice(1).some((k) => f[k] !== '')
}

onMounted(() => {
  fromRoute()
  run(0)
})
watch(() => route.query, (q, old) => {
  if (JSON.stringify(q) !== JSON.stringify(old) && JSON.stringify(q) !== JSON.stringify(params.value)) {
    fromRoute()
    run(0)
  }
})
</script>

<template>
  <div>
    <PageHeader title="Recherche" :crumbs="[{ label: 'LastHop' }]" :kpis="[{ value: state.total, label: 'Endpoints trouvés' }]" />
    <section class="content">
    <form class="filters" role="search" @submit.prevent="submit">
      <label class="grow">Recherche globale
        <input v-model.trim="f.q" type="search" maxlength="100" placeholder="IP, MAC (partielle), nom d’hôte, port, VLAN…" autocomplete="off" />
      </label>
      <button type="submit">Rechercher</button>
      <button type="button" class="link" @click="advanced = !advanced">{{ advanced ? 'Masquer' : 'Filtres avancés' }}</button>
      <fieldset v-if="advanced" class="advanced">
        <label>MAC<input v-model.trim="f.mac" maxlength="32" placeholder="aa:bb:cc… / aabb.ccdd…" /></label>
        <label>IP / CIDR<input v-model.trim="f.ip" maxlength="43" placeholder="10.0.0.5 ou 10.0.0.0/24" /></label>
        <label>VLAN<input v-model.trim="f.vlan" type="number" min="1" max="4094" /></label>
        <label>Nom d’hôte<input v-model.trim="f.hostname" maxlength="100" /></label>
        <label>Port<input v-model.trim="f.port" maxlength="64" placeholder="Gi1/0/3" /></label>
        <label>État
          <select v-model="f.active"><option value="">Tous</option><option value="true">Actifs</option><option value="false">Inactifs</option></select>
        </label>
      </fieldset>
    </form>
    <ErrorBanner :message="state.error" />
    <p class="toolbar">
      <span>{{ state.total }} résultat(s)</span>
      <a v-if="can('export')" :href="exportUrl" class="button" download><Icon name="download" :size="16" /> Exporter en CSV</a>
    </p>
    <DataTable :columns="columns" :data="state.items" :loading="state.loading" clickable empty="Aucun endpoint ne correspond." @row-click="open">
      <template #cell-mac="{ row }"><code>{{ row.mac }}</code></template>
      <template #cell-vlan="{ value }">{{ value ?? '—' }}</template>
      <template #cell-last_seen="{ value }">{{ dt(value) }}</template>
      <template #cell-active="{ value }"><Badge :kind="value ? 'ok' : 'muted'">{{ value ? 'actif' : 'inactif' }}</Badge></template>
    </DataTable>
    <Pager :total="state.total" :offset="state.offset" :limit="limit" @change="run" @limit="(n) => { limit = n; run(0) }" />

    <aside v-if="selected" class="panel" aria-label="Détail de l’endpoint">
      <h2>{{ selected.mac }} <small>{{ selected.ip }}</small></h2>
      <p>
        {{ selected.device }} / {{ selected.port }} (VLAN {{ selected.vlan ?? '—' }}) — vu pour la première fois le {{ dt(selected.first_seen) }}
      </p>
      <p v-if="can('realtime')"><RouterLink :to="{ name: 'locate', query: { q: selected.ip || selected.mac } }">Localiser maintenant (temps réel)</RouterLink></p>
      <h3>Historique des déplacements</h3>
      <ul class="timeline">
        <li v-for="(h, i) in history" :key="i">
          <time>{{ dt(h.ts) }}</time> <Badge>{{ h.change }}</Badge>
          <span v-if="h.old || h.new"> {{ h.old?.device }} {{ h.old?.port }} → {{ h.new?.device }} {{ h.new?.port }}</span>
        </li>
        <li v-if="!history.length">Aucun événement.</li>
      </ul>
    </aside>
    </section>
  </div>
</template>
