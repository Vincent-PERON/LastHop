<script setup>
// Diagnostic SNMP (lecture seule) : quelles tables LastHop sait lire sur l'équipement, ce qui manque et quoi faire.
import { ref } from 'vue'
import ErrorBanner from './ErrorBanner.vue'
import Badge from './Badge.vue'
import { post } from '../api/client.js'
import { waitJob } from '../utils/jobs.js'
import { ERROR_LABEL } from '../utils/format.js'

const props = defineProps({ device: { type: Object, required: true } })
const result = ref(null)
const error = ref('')
const busy = ref(false)

const KIND = { ok: 'ok', empty: 'warn', error: 'bad', partial: 'warn', missing: 'bad', na: 'muted' }
const LABEL = { ok: 'lisible', empty: 'vide', error: 'refusé', partial: 'partiel', missing: 'impossible', na: 'sans objet' }

async function run() {
  error.value = ''
  result.value = null
  busy.value = true
  try {
    const { job_id: id } = await post(`/api/v1/devices/${props.device.id}/diagnose`)
    const j = await waitJob(id)
    if (j.status === 'done') result.value = j.result
    else error.value = ERROR_LABEL[j.error_code] || `Diagnostic impossible (${j.error_code || 'erreur'}).`
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card" aria-labelledby="diag-title">
    <h2 id="diag-title">Diagnostic SNMP</h2>
    <p class="hint">Vérifie, sans rien modifier, quelles tables l’équipement expose à LastHop et ce que cela permet (ports, topologie, MAC, ARP, temps réel).</p>
    <p><button type="button" class="ghost" :disabled="busy" @click="run">{{ busy ? 'Diagnostic en cours…' : 'Lancer le diagnostic' }}</button></p>
    <ErrorBanner :message="error" />
    <template v-if="result">
      <p>Pilote utilisé : <strong>{{ result.driver }}</strong></p>
      <h3 class="h-sm">Ce que LastHop peut faire</h3>
      <ul class="diag-list">
        <li v-for="v in result.verdicts" :key="v.feature">
          <Badge :kind="KIND[v.level]">{{ LABEL[v.level] }}</Badge> <strong>{{ v.feature }}</strong> — {{ v.message }}
          <div v-if="v.advice" class="advice">{{ v.advice }}</div>
        </li>
      </ul>
      <details>
        <summary>Détail des tables lues</summary>
        <div class="table-wrap">
          <table>
            <thead><tr><th scope="col">Table</th><th scope="col">État</th><th scope="col">Lignes</th><th scope="col">Remarque</th></tr></thead>
            <tbody>
              <tr v-for="c in result.checks" :key="c.key">
                <td>{{ c.title }}</td>
                <td><Badge :kind="KIND[c.status]">{{ LABEL[c.status] }}</Badge></td>
                <td>{{ c.rows }}</td>
                <td>{{ c.detail || (c.sample || []).join(' · ') || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </template>
  </section>
</template>
