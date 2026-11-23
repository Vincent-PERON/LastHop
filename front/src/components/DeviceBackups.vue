<script setup>
// Sauvegarde d'un équipement : réglages SSH, approbation d'empreinte, lancement, versions, consultation et comparaison.
import { reactive, ref, computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import Badge from './Badge.vue'
import ErrorBanner from './ErrorBanner.vue'
import { get, post, put } from '../api/client.js'
import { can } from '../stores/session.js'
import { waitJob } from '../utils/jobs.js'
import { dt, ERROR_LABEL, RUN_STATUS } from '../utils/format.js'

const props = defineProps({ device: { type: Object, required: true } })
const emit = defineEmits(['changed'])

const profiles = ref([])
const versions = ref([])
const error = ref('')
const notice = ref('')
const busy = ref(false)
const lastRun = ref(null)
const view = ref(null)
const diff = ref(null)
const picks = ref([])
const cfg = reactive({ ssh_credential_id: props.device.ssh_credential_id || '', ssh_port: props.device.ssh_port ?? 22, ssh_allow_legacy: !!props.device.ssh_allow_legacy, backup_enabled: !!props.device.backup_enabled })
const hk = reactive({ job: null, fingerprint: '', typed: '', error: '' })
const canRun = can('backups:run')
const canEdit = can('inventory:write')

const KIND = { running: 'running (en cours)', startup: 'startup (démarrage)' }
const diffLines = computed(() => (diff.value ? diff.value.diff.split('\n') : []))
const lineClass = (l) => (l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : '')

async function load() {
  try {
    versions.value = await get(`/api/v1/devices/${props.device.id}/backups`)
    if (canEdit) profiles.value = await get('/api/v1/ssh-credentials').catch(() => [])
  } catch (e) {
    error.value = e.message
  }
}

async function saveSettings() {
  error.value = ''
  try {
    await put(`/api/v1/devices/${props.device.id}`, { ...cfg, ssh_credential_id: cfg.ssh_credential_id || null, ssh_port: Number(cfg.ssh_port) })
    notice.value = 'Réglages enregistrés.'
    emit('changed')
  } catch (e) {
    error.value = e.message
  }
}

async function checkHostKey() {
  Object.assign(hk, { job: null, fingerprint: '', typed: '', error: '' })
  try {
    const { job_id: id } = await post(`/api/v1/devices/${props.device.id}/ssh/hostkey`)
    const j = await waitJob(id, { tries: 30 })
    if (j.status !== 'done') hk.error = j.result?.message ? `${j.result.message} ${j.result.advice || ''}` : (ERROR_LABEL[j.error_code] || j.error_code)
    else Object.assign(hk, { job: j.id, fingerprint: j.result.fingerprint })
  } catch (e) {
    hk.error = e.message
  }
}

async function trust() {
  try {
    await post(`/api/v1/devices/${props.device.id}/ssh/trust`, { job_id: hk.job, fingerprint: hk.typed.trim() })
    notice.value = 'Empreinte approuvée : les sauvegardes peuvent maintenant se connecter à cet équipement.'
    Object.assign(hk, { job: null, fingerprint: '', typed: '' })
    emit('changed')
  } catch (e) {
    hk.error = e.message
  }
}

async function runNow() {
  busy.value = true
  error.value = ''
  notice.value = ''
  lastRun.value = null
  try {
    const { job_id: id } = await post(`/api/v1/devices/${props.device.id}/backup`)
    const j = await waitJob(id, { tries: 120 })
    const runs = await get('/api/v1/backups/runs', { device_id: props.device.id, limit: 1 })
    lastRun.value = runs.items[0] || null
    if (j.status === 'failed' && !lastRun.value) error.value = ERROR_LABEL[j.error_code] || j.error_code
    await load()
    emit('changed')
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function show(v, raw = false) {
  if (raw && !window.confirm('Afficher le contenu COMPLET (mots de passe et communities inclus) ? Cet accès est enregistré dans le journal d’audit.')) return
  diff.value = null
  try {
    view.value = await get(`/api/v1/backups/${v.id}`, raw ? { raw: 'true' } : {})
  } catch (e) {
    error.value = e.message
  }
}

async function compare() {
  const [a, b] = picks.value
  view.value = null
  try {
    diff.value = await get('/api/v1/backups/diff', { a, b })
  } catch (e) {
    error.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <section class="card">
    <h2>Sauvegarde de la configuration</h2>
    <ErrorBanner :message="error" />
    <p v-if="notice" class="notice" role="status">{{ notice }}</p>

    <form v-if="canEdit" class="form-grid" @submit.prevent="saveSettings">
      <label>Profil SSH
        <select v-model="cfg.ssh_credential_id"><option value="">— aucun —</option><option v-for="p in profiles" :key="p.id" :value="p.id">{{ p.name }} ({{ p.username }})</option></select>
      </label>
      <label>Port SSH<input v-model="cfg.ssh_port" type="number" min="1" max="65535" /></label>
      <label class="check"><input v-model="cfg.backup_enabled" type="checkbox" /> Sauvegarde automatique</label>
      <label class="check"><input v-model="cfg.ssh_allow_legacy" type="checkbox" /> Algorithmes SSH anciens (moins sûr)</label>
      <button type="submit">Enregistrer</button>
    </form>

    <h3>Empreinte SSH de l’équipement</h3>
    <p v-if="device.ssh_host_fingerprint">Approuvée : <code>{{ device.ssh_host_fingerprint }}</code></p>
    <p v-else class="warn">Aucune empreinte approuvée : par sécurité, aucune sauvegarde ne sera tentée tant qu’elle n’est pas validée.</p>
    <template v-if="canEdit">
      <button type="button" @click="checkHostKey">Vérifier l’empreinte SSH</button>
      <ErrorBanner :message="hk.error" />
      <div v-if="hk.fingerprint" class="card">
        <p>L’équipement présente cette empreinte : <code>{{ hk.fingerprint }}</code></p>
        <p class="hint">Comparez-la avec celle affichée sur l’équipement lui-même, puis <strong>ressaisissez-la</strong> pour confirmer (aucune approbation automatique).</p>
        <input v-model.trim="hk.typed" aria-label="Empreinte à confirmer" placeholder="SHA256:…" autocomplete="off" />
        <button type="button" :disabled="!hk.typed" @click="trust">Approuver cette empreinte</button>
      </div>
    </template>

    <h3>Sauvegardes</h3>
    <p v-if="canRun"><button type="button" :disabled="busy" @click="runNow">{{ busy ? 'Sauvegarde en cours…' : 'Sauvegarder maintenant' }}</button></p>
    <div v-if="lastRun" :class="['result', lastRun.status === 'success' ? 'ok' : 'bad']" role="status">
      <Badge :kind="RUN_STATUS[lastRun.status]?.[1]">{{ RUN_STATUS[lastRun.status]?.[0] }}</Badge> {{ lastRun.summary }}
      <RouterLink :to="{ name: 'backups', query: { device: device.id } }">Voir le journal complet</RouterLink>
    </div>

    <table v-if="versions.length">
      <thead><tr><th scope="col"></th><th scope="col">Date</th><th scope="col">Type</th><th scope="col">Taille</th><th scope="col">État</th><th scope="col"></th></tr></thead>
      <tbody>
        <tr v-for="v in versions" :key="v.id">
          <td><input v-model="picks" type="checkbox" :value="v.id" :disabled="picks.length >= 2 && !picks.includes(v.id)" :aria-label="`Comparer la version du ${dt(v.created_at)}`" /></td>
          <td>{{ dt(v.created_at) }}</td>
          <td>{{ KIND[v.kind] }}</td>
          <td>{{ v.size_bytes }} octets</td>
          <td><Badge :kind="v.status === 'success' ? 'ok' : 'muted'">{{ v.status === 'success' ? 'nouvelle version' : 'identique' }}</Badge></td>
          <td class="actions"><button type="button" @click="show(v)">Voir</button> <button type="button" class="link" @click="show(v, true)">Contenu brut</button></td>
        </tr>
      </tbody>
    </table>
    <p v-else class="hint">Aucune version enregistrée pour le moment.</p>
    <p v-if="picks.length === 2"><button type="button" @click="compare">Comparer les 2 versions sélectionnées</button></p>

    <div v-if="view" class="panel">
      <h3>{{ KIND[view.kind] }} — {{ dt(view.created_at) }} <Badge :kind="view.masked ? 'ok' : 'warn'">{{ view.masked ? 'secrets masqués' : 'contenu complet' }}</Badge></h3>
      <pre class="config">{{ view.content }}</pre>
    </div>
    <div v-if="diff" class="panel">
      <h3>Différences : +{{ diff.added }} / −{{ diff.removed }} ligne(s) <small>(secrets masqués)</small></h3>
      <pre class="config"><span v-for="(l, i) in diffLines" :key="i" :class="lineClass(l)">{{ l }}
</span></pre>
    </div>
  </section>
</template>
