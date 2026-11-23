<script setup>
// Endpoints (équipements terminaux) vus sur un port : affichés dans une fenêtre modale, sans quitter la fiche équipement.
import { reactive, ref, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import Modal from './Modal.vue'
import Badge from './Badge.vue'
import Pager from './Pager.vue'
import ErrorBanner from './ErrorBanner.vue'
import { get } from '../api/client.js'
import { dt, ROLE_LABEL } from '../utils/format.js'

const props = defineProps({ device: { type: Object, required: true }, port: { type: Object, required: true } })
const emit = defineEmits(['close'])

const limit = ref(10)
const data = reactive({ items: [], total: 0, offset: 0, loading: true, error: '' })

async function load(offset = 0) {
  data.loading = true
  data.error = ''
  try {
    // filtre EXACT sur l'identifiant du port (« Gi1/0/1 » ne ramène pas « Gi1/0/10 »)
    const r = await get('/api/v1/endpoints', { interface_id: props.port.id, limit: limit.value, offset })
    Object.assign(data, { items: r.items, total: r.total, offset })
  } catch (e) {
    data.error = e.message
  } finally {
    data.loading = false
  }
}

onMounted(() => load())
</script>

<template>
  <Modal :title="`Endpoints du port ${port.name}`" wide @close="emit('close')">
    <p class="port-sum">
      <strong>{{ device.name }}</strong> · {{ port.name }}
      <Badge :kind="port.oper_status === 1 ? 'ok' : 'bad'">{{ port.oper_status === 1 ? 'up' : 'down' }}</Badge>
      <Badge :kind="port.role === 'uplink' ? 'warn' : 'ok'">{{ ROLE_LABEL[port.role] }}</Badge>
      <span v-if="port.alias" class="hint"> — {{ port.alias }}</span>
    </p>
    <p v-if="port.role === 'uplink'" class="hint">
      Ce port est un <strong>uplink</strong> : les adresses MAC qui y transitent ne sont pas conservées comme endpoints (elles sont rattachées au switch d’accès où elles sont réellement connectées).
    </p>
    <ErrorBanner :message="data.error" />
    <div class="table-wrap">
      <table>
        <thead><tr><th scope="col">MAC</th><th scope="col">IP</th><th scope="col">Nom d’hôte</th><th scope="col">Constructeur</th><th scope="col">VLAN</th><th scope="col">Dernière vue</th><th scope="col">État</th></tr></thead>
        <tbody>
          <tr v-for="e in data.items" :key="e.id">
            <td><code>{{ e.mac }}</code></td>
            <td>{{ e.ip || '—' }}</td>
            <td>{{ e.hostname || '—' }}</td>
            <td>{{ e.vendor || '—' }}</td>
            <td>{{ e.vlan ?? '—' }}</td>
            <td>{{ dt(e.last_seen) }}</td>
            <td><Badge :kind="e.active ? 'ok' : 'muted'">{{ e.active ? 'actif' : 'inactif' }}</Badge></td>
          </tr>
          <tr v-if="data.loading"><td class="empty" colspan="7">Chargement…</td></tr>
          <tr v-else-if="!data.items.length"><td class="empty" colspan="7">Aucun endpoint connu sur ce port.</td></tr>
        </tbody>
      </table>
    </div>
    <Pager :total="data.total" :offset="data.offset" :limit="limit" :sizes="[10, 25, 50]" @change="load" @limit="(n) => { limit = n; load(0) }" />
    <template #footer>
      <RouterLink :to="{ name: 'search', query: { device_id: device.id, port: port.name } }" @click="emit('close')">Ouvrir dans la recherche complète ›</RouterLink>
      <button type="button" class="ghost" @click="emit('close')">Fermer</button>
    </template>
  </Modal>
</template>
