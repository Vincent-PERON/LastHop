<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, onMounted, onBeforeUnmount } from 'vue'
import DataTable from '../components/DataTable.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, post, del } from '../api/client.js'
import { dt } from '../utils/format.js'

const tokens = ref([])
const error = ref('')
const fresh = ref('') // secret affiché une seule fois, uniquement en mémoire (jamais stocké)
const SCOPES = [['read', 'Lecture de l’inventaire'], ['search', 'Recherche d’endpoints'], ['topology', 'Lecture de la topologie'], ['realtime', 'Localisation en direct'], ['export', 'Export CSV']]
const form = reactive({ name: '', scopes: ['search'], expires_in_days: 90 })

const columns = [
  { accessorKey: 'name', header: 'Nom' },
  { accessorKey: 'prefix', header: 'Préfixe' },
  { id: 'scopes', header: 'Portées', accessorFn: (t) => t.scopes.join(', ') },
  { accessorKey: 'expires_at', header: 'Expire' },
  { accessorKey: 'last_used_at', header: 'Dernier usage' },
  { id: 'actions', header: '', accessorFn: () => '' },
]

async function load() {
  try {
    tokens.value = await get('/api/v1/tokens')
  } catch (e) {
    error.value = e.message
  }
}

async function create() {
  error.value = ''
  try {
    const r = await post('/api/v1/tokens', { name: form.name, scopes: form.scopes, expires_in_days: Number(form.expires_in_days) })
    fresh.value = r.token
    form.name = ''
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function revoke(t) {
  if (!window.confirm(`Révoquer le token « ${t.name} » ?`)) return
  try {
    await del(`/api/v1/tokens/${t.id}`)
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(fresh.value)
  } catch {
    /* copie manuelle */
  }
}

onMounted(load)
onBeforeUnmount(() => {
  fresh.value = ''
})
</script>

<template>
  <div>
    <PageHeader title="Tokens d’API" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <p class="hint">Pour automatiser des requêtes (en-tête <code>Authorization: Bearer …</code>). Un token ne dépasse jamais vos propres droits et ne peut pas en créer d’autres.</p>
    <ErrorBanner :message="error" />
    <div v-if="fresh" class="card notice" role="status">
      <strong>Copiez ce token maintenant : il ne sera plus jamais affiché.</strong>
      <code class="secret">{{ fresh }}</code>
      <button type="button" @click="copy">Copier</button>
      <button type="button" class="link" @click="fresh = ''">Fermer</button>
    </div>
    <form class="card form-grid" @submit.prevent="create">
      <label>Nom<input v-model.trim="form.name" required maxlength="100" pattern="[\w .@()\-]+" /></label>
      <label>Validité (jours)<input v-model="form.expires_in_days" type="number" min="1" max="365" /></label>
      <fieldset>
        <legend>Portées</legend>
        <label v-for="[k, label] in SCOPES" :key="k" class="check"><input v-model="form.scopes" type="checkbox" :value="k" /> {{ label }}</label>
      </fieldset>
      <button type="submit" :disabled="!form.scopes.length">Créer le token</button>
    </form>
    <DataTable :columns="columns" :data="tokens" empty="Aucun token.">
      <template #cell-expires_at="{ value }">{{ dt(value) }}</template>
      <template #cell-last_used_at="{ value }">{{ dt(value) }}</template>
      <template #cell-actions="{ row }"><Badge v-if="row.revoked_at" kind="muted">révoqué</Badge><button v-else type="button" class="danger" @click="revoke(row)">Révoquer</button></template>
    </DataTable>
    </section>
  </div>
</template>
