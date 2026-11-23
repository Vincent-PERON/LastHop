<script setup>
import PageHeader from '../components/PageHeader.vue'
import { ref, reactive, onMounted } from 'vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get, put } from '../api/client.js'

const values = ref({})
const edit = reactive({})
const error = ref('')
const saved = ref('')

const LABELS = {
  snmp_v2c_enabled: ['SNMP v2c autorisé', 'Désactivé par défaut : v3 authPriv est recommandé.'],
  snmp_allowed_cidrs: ['Réseaux SNMP autorisés (un CIDR par ligne)', 'Aucune cible n’est interrogeable tant que cette liste est vide.'],
  uplink_mac_threshold: ['Seuil de MAC par port (uplink)', 'Au-delà, un port est classé uplink.'],
  trunk_min_tagged_vlans: ['VLAN tagués minimum pour un trunk', ''],
  topology_interval_s: ['Intervalle de collecte de topologie (s)', ''],
  retention_days: ['Rétention (jours)', 'Endpoints et historiques ; l’audit n’est jamais purgé.'],
  snmp_max_concurrency: ['Concurrence SNMP maximale', ''],
  realtime_timeout_s: ['Délai global de la recherche en direct (s)', ''],
}

async function load() {
  try {
    values.value = await get('/api/v1/settings')
    for (const [k, v] of Object.entries(values.value)) edit[k] = Array.isArray(v) ? v.join('\n') : v
  } catch (e) {
    error.value = e.message
  }
}

async function save(key) {
  error.value = ''
  saved.value = ''
  const cur = values.value[key]
  let v = edit[key]
  if (Array.isArray(cur)) v = String(v).split('\n').map((x) => x.trim()).filter(Boolean)
  else if (typeof cur === 'number') v = Number(v)
  try {
    await put(`/api/v1/settings/${key}`, { value: v })
    saved.value = `« ${LABELS[key]?.[0] || key} » enregistré.`
    await load()
  } catch (e) {
    error.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <PageHeader title="Paramètres" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <ErrorBanner :message="error" />
    <p v-if="saved" class="notice" role="status">{{ saved }}</p>
    <form v-for="(v, key) in values" :key="key" class="card setting" @submit.prevent="save(key)">
      <label :for="`s-${key}`">{{ LABELS[key]?.[0] || key }}</label>
      <input v-if="typeof v === 'boolean'" :id="`s-${key}`" v-model="edit[key]" type="checkbox" />
      <textarea v-else-if="Array.isArray(v)" :id="`s-${key}`" v-model="edit[key]" rows="3" placeholder="10.20.0.0/16"></textarea>
      <input v-else :id="`s-${key}`" v-model="edit[key]" type="number" />
      <small>{{ LABELS[key]?.[1] }}</small>
      <button type="submit">Enregistrer</button>
    </form>
    </section>
  </div>
</template>
