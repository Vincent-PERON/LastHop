<script setup>
// Authentification (super admin) : fournisseurs d'identité Keycloak, Entra ID, Google Workspace, OIDC générique et LDAP direct.
import { ref, onMounted } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import DataTable from '../components/DataTable.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import AuthProviderForm from '../components/AuthProviderForm.vue'
import { get, put, post, del } from '../api/client.js'
import { PRESETS } from '../utils/format.js'

const providers = ref([])
const error = ref('')
const editor = ref(null) // { provider } | { provider: null } pour une création
const results = ref({}) // id -> { ok, message }

const columns = [
  { accessorKey: 'name', header: 'Nom' },
  { id: 'type', header: 'Type', accessorFn: (p) => PRESETS[p.preset]?.label || p.preset },
  { id: 'state', header: 'État', accessorFn: (p) => (p.enabled ? 'actif' : 'désactivé') },
  { id: 'actions', header: '', accessorFn: () => '' },
]

async function load() {
  try {
    providers.value = await get('/api/v1/auth-providers')
  } catch (e) {
    error.value = e.message
  }
}

async function toggle(p) {
  error.value = ''
  try {
    await put(`/api/v1/auth-providers/${p.id}`, { enabled: !p.enabled })
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function test(p) {
  results.value = { ...results.value, [p.id]: { ok: null, message: 'Test en cours…' } }
  try {
    results.value = { ...results.value, [p.id]: await post(`/api/v1/auth-providers/${p.id}/test`) }
  } catch (e) {
    results.value = { ...results.value, [p.id]: { ok: false, message: e.message } }
  }
}

async function remove(p) {
  if (!window.confirm(`Supprimer « ${p.name} » ? Ses utilisateurs ne pourront plus se connecter par ce fournisseur.`)) return
  try {
    await del(`/api/v1/auth-providers/${p.id}`)
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function saved() {
  editor.value = null
  await load()
}

onMounted(load)
</script>

<template>
  <div>
    <PageHeader title="Authentification" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
      <p class="hint">
        Le <strong>compte super admin local</strong> reste toujours disponible. Les fournisseurs ci-dessous ajoutent la connexion par
        Keycloak, Microsoft Entra ID, Google Workspace ou un annuaire LDAP ; leurs utilisateurs sont <strong>opérateurs ou lecteurs</strong> (jamais super admin).
        Les secrets sont chiffrés et ne sont jamais réaffichés.
      </p>
      <ErrorBanner :message="error" />
      <p><button type="button" @click="editor = { provider: null }">Ajouter un fournisseur</button></p>
      <DataTable :columns="columns" :data="providers" empty="Aucun fournisseur : seul le compte local peut se connecter.">
        <template #cell-state="{ row }"><Badge :kind="row.enabled ? 'ok' : 'muted'">{{ row.enabled ? 'actif' : 'désactivé' }}</Badge></template>
        <template #cell-name="{ row }">
          <strong>{{ row.name }}</strong>
          <div v-if="row.config?.insecure"><Badge kind="bad">connexion non chiffrée</Badge></div>
          <div v-if="results[row.id]" :class="['test-result', results[row.id].ok ? 'ok' : results[row.id].ok === false ? 'bad' : '']" role="status">{{ results[row.id].message }}</div>
        </template>
        <template #cell-actions="{ row }">
          <button type="button" class="ghost" @click="test(row)">Tester</button>
          <button type="button" class="ghost" @click="toggle(row)">{{ row.enabled ? 'Désactiver' : 'Activer' }}</button>
          <button type="button" class="ghost" @click="editor = { provider: row }">Modifier</button>
          <button type="button" class="danger" @click="remove(row)">Supprimer</button>
        </template>
      </DataTable>
    </section>
    <AuthProviderForm v-if="editor" :provider="editor.provider" @saved="saved" @close="editor = null" />
  </div>
</template>
