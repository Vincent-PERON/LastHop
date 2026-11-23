<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, onMounted } from 'vue'
import DataTable from '../components/DataTable.vue'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, post, del } from '../api/client.js'

const profiles = ref([])
const error = ref('')
const blank = () => ({ name: '', username: '', auth_type: 'password', password: '', private_key: '', passphrase: '' })
const form = reactive(blank())

const columns = [
  { accessorKey: 'name', header: 'Nom' },
  { accessorKey: 'username', header: 'Utilisateur' },
  { accessorKey: 'auth_type', header: 'Authentification' },
  { accessorKey: 'devices_using', header: 'Équipements' },
  { id: 'actions', header: '', accessorFn: () => '' },
]

async function load() {
  try {
    profiles.value = await get('/api/v1/ssh-credentials')
  } catch (e) {
    error.value = e.message
  }
}

async function create() {
  error.value = ''
  const body = { name: form.name, username: form.username, auth_type: form.auth_type }
  if (form.auth_type === 'password') body.password = form.password
  else Object.assign(body, { private_key: form.private_key, ...(form.passphrase ? { passphrase: form.passphrase } : {}) })
  try {
    await post('/api/v1/ssh-credentials', body)
    Object.assign(form, blank()) // secrets effacés de la mémoire de la page dès l'envoi
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function remove(p) {
  if (!window.confirm(`Supprimer le profil « ${p.name} » ? Les équipements concernés ne pourront plus être sauvegardés.`)) return
  try {
    await del(`/api/v1/ssh-credentials/${p.id}`)
    await load()
  } catch (e) {
    error.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <PageHeader title="Profils SSH (sauvegarde)" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <p class="hint">
      Compte de <strong>lecture seule</strong> recommandé (il doit pouvoir afficher la configuration). Le secret est chiffré côté serveur et n’est jamais réaffiché.
    </p>
    <ErrorBanner :message="error" />
    <form class="card form-grid" autocomplete="off" @submit.prevent="create">
      <label>Nom<input v-model.trim="form.name" required maxlength="100" /></label>
      <label>Utilisateur<input v-model.trim="form.username" required maxlength="64" autocomplete="off" /></label>
      <label>Authentification
        <select v-model="form.auth_type"><option value="password">Mot de passe</option><option value="key">Clé privée</option></select>
      </label>
      <label v-if="form.auth_type === 'password'">Mot de passe<input v-model="form.password" type="password" required maxlength="256" autocomplete="new-password" /></label>
      <template v-else>
        <label>Clé privée (PEM / OpenSSH)<textarea v-model="form.private_key" required rows="4" spellcheck="false" autocomplete="off"></textarea></label>
        <label>Passphrase (si la clé en a une)<input v-model="form.passphrase" type="password" maxlength="256" autocomplete="new-password" /></label>
      </template>
      <button type="submit">Créer le profil</button>
    </form>
    <DataTable :columns="columns" :data="profiles" empty="Aucun profil SSH.">
      <template #cell-auth_type="{ value }"><Badge>{{ value === 'key' ? 'clé' : 'mot de passe' }}</Badge></template>
      <template #cell-actions="{ row }"><button type="button" class="danger" @click="remove(row)">Supprimer</button></template>
    </DataTable>
    </section>
  </div>
</template>
