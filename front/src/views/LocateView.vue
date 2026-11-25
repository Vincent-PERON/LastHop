<script setup>
import PageHeader from '../components/PageHeader.vue'
import { reactive, ref, onMounted, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import Badge from '../components/Badge.vue'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get } from '../api/client.js'
import { startRealtime, openStream } from '../api/realtime.js'
import { dt, ERROR_LABEL } from '../utils/format.js'

const route = useRoute()
const query = ref('')
const siteId = ref('')
const sites = ref([])
const run = reactive({ active: false, steps: [], devices: [], result: null, failure: null, error: '' })
let stream = null

const STEP_LABEL = {
  started: 'Recherche lancée',
  arp_resolving: 'Recherche de l’adresse MAC de l’IP auprès des routeurs',
  arp_resolved: 'MAC trouvée',
  fdb_querying: 'Recherche du port sur les switchs (table des adresses MAC)',
}

function reset() {
  stream?.close()
  Object.assign(run, { active: false, steps: [], devices: [], result: null, failure: null, error: '' })
}

function onEvent({ type, data }) {
  if (type === 'device_queried') run.devices.push(data)
  else if (type === 'hop') run.steps.push({ text: `Saut ${data.device} — port ${data.port ?? '?'} (${data.role})`, data })
  else if (type === 'located') run.result = data
  else if (type === 'failed') run.failure = data
  else if (type === 'auth_expired') run.error = 'Session expirée : reconnectez-vous.'
  else if (type === 'done') run.active = false
  else if (STEP_LABEL[type]) run.steps.push({ text: type === 'arp_resolved' ? `${STEP_LABEL[type]} : ${data.mac} (via ${data.gateway})` : STEP_LABEL[type], data })
}

async function submit() {
  reset()
  run.active = true
  try {
    const { events_url: url } = await startRealtime(query.value.trim(), siteId.value)
    stream = openStream(url, onEvent, () => {
      run.active = false
      run.error = 'Flux interrompu.'
    })
  } catch (e) {
    run.active = false
    run.error = e.message
  }
}

onMounted(async () => {
  if (typeof route.query.q === 'string') query.value = route.query.q
  try {
    sites.value = await get('/api/v1/sites')
  } catch {
    /* périmètre global par défaut */
  }
})
onBeforeUnmount(() => stream?.close())
</script>

<template>
  <div>
    <PageHeader title="Localisation en direct" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <form class="filters" @submit.prevent="submit">
      <label class="grow">Adresse IP ou MAC
        <input v-model.trim="query" required maxlength="64" placeholder="10.50.0.30 · aa:bb:cc:dd:ee:ff · aabb.ccdd.eeff" autocomplete="off" />
      </label>
      <label>Site
        <select v-model="siteId"><option value="">Tous</option><option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option></select>
      </label>
      <button type="submit" :disabled="run.active">{{ run.active ? 'Recherche en cours…' : 'Localiser' }}</button>
      <button v-if="run.active" type="button" class="link" @click="reset">Annuler</button>
    </form>
    <p class="hint">Interroge les équipements en direct (SNMP lecture seule). Chaque recherche est auditée.</p>
    <ErrorBanner :message="run.error" />

    <div v-if="run.steps.length || run.devices.length" class="progress" aria-live="polite">
      <ol>
        <li v-for="(s, i) in run.steps" :key="i">{{ s.text }}</li>
      </ol>
      <ul class="chips">
        <li v-for="(d, i) in run.devices" :key="i">
          <Badge :kind="d.status === 'found' ? 'ok' : d.status === 'not_found' ? 'muted' : 'bad'">{{ d.device }}</Badge>
          <small>{{ d.status === 'found' ? (d.port ? `port ${d.port}` : 'trouvée') : d.status === 'not_found' ? 'absente' : (ERROR_LABEL[d.code] || d.code) }}</small>
        </li>
      </ul>
    </div>

    <article v-if="run.result" class="result ok" aria-label="Résultat">
      <h2>{{ run.result.location.device }} — port {{ run.result.location.port }}</h2>
      <dl>
        <dt>MAC</dt><dd><code>{{ run.result.mac }}</code></dd>
        <dt>IP</dt><dd>{{ run.result.ip || '—' }}<template v-if="run.result.known_ips?.length > 1"> ({{ run.result.known_ips.join(', ') }})</template></dd>
        <dt>VLAN</dt><dd>{{ run.result.location.vlan ?? '—' }}</dd>
        <dt>Constructeur</dt><dd>{{ run.result.vendor || '—' }}</dd>
        <dt>Nom d’hôte</dt><dd>{{ run.result.hostname || '—' }}</dd>
        <dt>Première / dernière vue</dt><dd>{{ dt(run.result.first_seen) }} / {{ dt(run.result.last_seen) }}</dd>
        <dt>Durée</dt><dd>{{ run.result.elapsed_ms }} ms</dd>
      </dl>
      <h3>Chaîne d’uplinks</h3>
      <ol class="chain">
        <li v-for="(h, i) in run.result.chain" :key="i">{{ h.device }} <small>port {{ h.port }}</small></li>
        <li><strong>{{ run.result.location.device }}</strong> <small>port {{ run.result.location.port }} (accès)</small></li>
      </ol>
      <p v-for="(w, i) in run.result.warnings" :key="i" class="warn">⚠ {{ w.message }}</p>
    </article>

    <article v-if="run.failure" class="result bad" aria-label="Échec">
      <h2>{{ ERROR_LABEL[run.failure.error_code] || run.failure.error_code }}</h2>
      <p>{{ run.failure.message }}</p>
    </article>
    </section>
  </div>
</template>
