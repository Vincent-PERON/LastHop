<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, onMounted } from 'vue'
import DataTable from '../components/DataTable.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, post, del } from '../api/client.js'

const creds = ref([])
const settings = ref({})
const error = ref('')
const blank = () => ({ name: '', version: 'v3', v3_username: '', auth_proto: 'sha256', priv_proto: 'aes128', auth_key: '', priv_key: '', community: '', allow_legacy_algos: false })
const form = reactive(blank())

const columns = [
  { accessorKey: 'name', header: 'Nom' },
  { accessorKey: 'version', header: 'Version' },
  { id: 'algos', header: 'Algorithmes', accessorFn: (c) => (c.version === 'v3' ? `${c.auth_proto} / ${c.priv_proto}` : '—') },
  { accessorKey: 'devices_using', header: 'Équipements' },
  { id: 'actions', header: '', accessorFn: () => '' },
]

async function load() {
  try {
    creds.value = await get('/api/v1/credentials')
    settings.value = await get('/api/v1/settings')
  } catch (e) {
    error.value = e.message
  }
}

async function create() {
  error.value = ''
  const body = { name: form.name, version: form.version }
  if (form.version === 'v2c') body.community = form.community
  else Object.assign(body, { v3_username: form.v3_username, auth_proto: form.auth_proto, priv_proto: form.priv_proto, auth_key: form.auth_key, priv_key: form.priv_key, allow_legacy_algos: form.allow_legacy_algos })
  try {
    await post('/api/v1/credentials', body)
    Object.assign(form, blank()) // les secrets saisis sont effacés immédiatement ; le serveur ne les renverra jamais
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function remove(c) {
  if (!window.confirm(`Supprimer le profil « ${c.name} » ?`)) return
  try {
    await del(`/api/v1/credentials/${c.id}`)
    await load()
  } catch (e) {
    error.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <PageHeader title="Profils d’identifiants SNMP" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <p class="hint">Les secrets sont chiffrés côté serveur et ne sont jamais réaffichés.</p>
    <ErrorBanner :message="error" />
    <form class="card form-grid" autocomplete="off" @submit.prevent="create">
      <label>Nom<input v-model.trim="form.name" required maxlength="100" /></label>
      <label>Version
        <select v-model="form.version"><option value="v3">SNMPv3 (authPriv)</option><option value="v2c" :disabled="!settings.snmp_v2c_enabled">SNMPv2c{{ settings.snmp_v2c_enabled ? '' : ' (désactivé)' }}</option></select>
      </label>
      <template v-if="form.version === 'v3'">
        <label>Utilisateur<input v-model.trim="form.v3_username" required maxlength="32" autocomplete="off" /></label>
        <label>Authentification
          <select v-model="form.auth_proto"><option>sha256</option><option>sha384</option><option>sha512</option><option>sha224</option><option value="sha1">sha1 (héritage)</option></select>
        </label>
        <label>Clé d’authentification<input v-model="form.auth_key" type="password" required minlength="8" maxlength="128" autocomplete="new-password" /></label>
        <label>Chiffrement
          <select v-model="form.priv_proto"><option>aes128</option><option>aes192</option><option>aes256</option></select>
        </label>
        <label>Clé de chiffrement<input v-model="form.priv_key" type="password" required minlength="8" maxlength="128" autocomplete="new-password" /></label>
        <label v-if="form.auth_proto === 'sha1'" class="check"><input v-model="form.allow_legacy_algos" type="checkbox" required /> J’accepte l’algorithme hérité SHA-1 (équipement ne supportant pas mieux)</label>
      </template>
      <label v-else>Community<input v-model="form.community" type="password" required minlength="6" maxlength="64" autocomplete="new-password" /></label>
      <button type="submit">Créer le profil</button>
    </form>
    <DataTable :columns="columns" :data="creds" empty="Aucun profil.">
      <template #cell-version="{ value }"><Badge :kind="value === 'v3' ? 'ok' : 'warn'">{{ value }}</Badge></template>
      <template #cell-actions="{ row }"><button type="button" class="danger" @click="remove(row)">Supprimer</button></template>
    </DataTable>
    </section>
  </div>
</template>
