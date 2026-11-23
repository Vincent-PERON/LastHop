<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, onMounted } from 'vue'
import DataTable from '../components/DataTable.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, post } from '../api/client.js'
import { waitJob } from '../utils/jobs.js'
import { ERROR_LABEL } from '../utils/format.js'

const creds = ref([])
const sites = ref([])
const form = reactive({ cidr: '', credential_id: '', port: 161 })
const error = ref('')
const notice = ref('')
const busy = ref(false)
const job = ref(null)
const picks = reactive({})

const columns = [
  { id: 'pick', header: '', accessorFn: () => '' },
  { accessorKey: 'ip', header: 'IP' },
  { accessorKey: 'sys_name', header: 'sysName' },
  { id: 'model', header: 'Constructeur / modèle', accessorFn: (h) => [h.vendor, h.model].filter(Boolean).join(' ') },
  { accessorKey: 'driver', header: 'Driver' },
  { id: 'name', header: 'Nom dans l’inventaire', accessorFn: () => '' },
  { id: 'role', header: 'Rôle', accessorFn: () => '' },
]

async function start() {
  error.value = ''
  notice.value = ''
  job.value = null
  busy.value = true
  try {
    const { job_id: id } = await post('/api/v1/discovery', { cidr: form.cidr, credential_id: form.credential_id, port: Number(form.port) })
    const j = await waitJob(id, { tries: 180 })
    if (j.status !== 'done') throw new Error(ERROR_LABEL[j.error_code] || j.error_code)
    job.value = j
    for (const h of j.result.hosts) picks[h.ip] = { on: !h.already_registered, name: h.sys_name || h.ip, role: 'access', site_id: '' }
    notice.value = `${j.result.found} équipement(s) répondant sur ${j.result.scanned} adresse(s) scannées.`
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function adopt() {
  const items = Object.entries(picks).filter(([, v]) => v.on).map(([ip, v]) => ({ ip, name: v.name, role: v.role, site_id: v.site_id || null }))
  if (!items.length) return
  try {
    const r = await post(`/api/v1/discovery/${job.value.id}/adopt`, { items })
    notice.value = `${r.created.length} équipement(s) ajouté(s) à l’inventaire.`
    job.value = null
  } catch (e) {
    error.value = e.message
  }
}

onMounted(async () => {
  try {
    creds.value = await get('/api/v1/credentials')
    sites.value = await get('/api/v1/sites')
  } catch (e) {
    error.value = e.message
  }
})
</script>

<template>
  <div>
    <PageHeader title="Découverte par plage CIDR" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <p class="hint">Seules les plages incluses dans les réseaux SNMP autorisés (Paramètres) sont analysées ; 1024 adresses maximum.</p>
    <ErrorBanner :message="error" />
    <form class="filters" @submit.prevent="start">
      <label>Plage CIDR<input v-model.trim="form.cidr" required maxlength="43" placeholder="10.20.0.0/24" /></label>
      <label>Profil SNMP
        <select v-model="form.credential_id" required><option value="" disabled>Choisir…</option><option v-for="c in creds" :key="c.id" :value="c.id">{{ c.name }} ({{ c.version }})</option></select>
      </label>
      <label>Port<input v-model="form.port" type="number" min="1" max="65535" /></label>
      <button type="submit" :disabled="busy">{{ busy ? 'Analyse en cours…' : 'Lancer la découverte' }}</button>
    </form>
    <p v-if="notice" class="notice" role="status">{{ notice }}</p>
    <template v-if="job">
      <DataTable :columns="columns" :data="job.result.hosts" row-key="ip" empty="Aucun équipement n’a répondu.">
        <template #cell-pick="{ row }"><input v-model="picks[row.ip].on" type="checkbox" :aria-label="`Adopter ${row.ip}`" /></template>
        <template #cell-driver="{ value }"><Badge>{{ value }}</Badge></template>
        <template #cell-name="{ row }"><input v-model.trim="picks[row.ip].name" maxlength="100" :aria-label="`Nom de ${row.ip}`" /> <Badge v-if="row.already_registered" kind="muted">déjà inventorié</Badge></template>
        <template #cell-role="{ row }">
          <select v-model="picks[row.ip].role" :aria-label="`Rôle de ${row.ip}`"><option value="core">cœur</option><option value="distribution">distribution</option><option value="access">accès</option></select>
          <select v-model="picks[row.ip].site_id" :aria-label="`Site de ${row.ip}`"><option value="">—</option><option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option></select>
        </template>
      </DataTable>
      <p><button type="button" @click="adopt">Ajouter la sélection à l’inventaire</button></p>
    </template>
    </section>
  </div>
</template>
