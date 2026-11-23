<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, onMounted } from 'vue'
import DataTable from '../components/DataTable.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get } from '../api/client.js'
import { dt } from '../utils/format.js'

const rows = ref([])
const error = ref('')
const verify = ref('')
const f = reactive({ action: '' })
const done = ref(false)

const columns = [
  { accessorKey: 'ts', header: 'Date' },
  { accessorKey: 'actor_label', header: 'Acteur' },
  { accessorKey: 'action', header: 'Action' },
  { accessorKey: 'outcome', header: 'Résultat' },
  { accessorKey: 'target_type', header: 'Cible' },
  { accessorKey: 'source_ip', header: 'IP source' },
  { id: 'details', header: 'Détails', accessorFn: (r) => JSON.stringify(r.details) },
]

async function load(reset = true) {
  error.value = ''
  try {
    const before = !reset && rows.value.length ? rows.value[rows.value.length - 1].id : undefined
    const page = await get('/api/v1/audit', { limit: 100, before_id: before, action: f.action || undefined })
    rows.value = reset ? page : [...rows.value, ...page]
    done.value = page.length < 100
  } catch (e) {
    error.value = e.message
  }
}

async function check() {
  try {
    const r = await get('/api/v1/audit/verify')
    verify.value = r.intact ? 'Chaîne d’audit intacte.' : `⚠ Chaîne ROMPUE à partir de l’entrée ${r.first_broken_id}.`
  } catch (e) {
    error.value = e.message
  }
}

onMounted(() => load())
</script>

<template>
  <div>
    <PageHeader title="Journal d’audit" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <form class="filters" @submit.prevent="load()">
      <label>Action<input v-model.trim="f.action" maxlength="64" pattern="[a-z_.]*" placeholder="realtime.search" /></label>
      <button type="submit">Filtrer</button>
      <button type="button" @click="check">Vérifier l’intégrité</button>
    </form>
    <ErrorBanner :message="error" />
    <p v-if="verify" class="notice" role="status">{{ verify }}</p>
    <DataTable :columns="columns" :data="rows" empty="Aucune entrée.">
      <template #cell-ts="{ value }">{{ dt(value) }}</template>
      <template #cell-outcome="{ value }"><Badge :kind="value === 'success' ? 'ok' : 'bad'">{{ value }}</Badge></template>
      <template #cell-details="{ value }"><code class="small">{{ value }}</code></template>
    </DataTable>
    <p v-if="!done"><button type="button" @click="load(false)">Charger plus</button></p>
    </section>
  </div>
</template>
