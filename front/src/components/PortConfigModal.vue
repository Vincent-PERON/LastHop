<script setup>
// Configuration d'un port (super admin) : mode accès/trunk, VLAN d'accès, VLAN natif (PVID), VLAN autorisés.
// Déroulé : formulaire → APERÇU des commandes exactes (+ alertes) → confirmation → exécution → résultat.
// Les VLAN proposés sont ceux que l'équipement connaît ; la vraie validation reste côté serveur.
import { reactive, ref, computed, onMounted } from 'vue'
import Modal from './Modal.vue'
import ErrorBanner from './ErrorBanner.vue'
import { get, post } from '../api/client.js'
import { waitJob } from '../utils/jobs.js'

const props = defineProps({ device: { type: Object, required: true }, port: { type: Object, required: true } })
const emit = defineEmits(['close', 'changed'])

const step = ref('form') // form | preview | running | result
const vlans = ref([])
const loadingVlans = ref(true)
const error = ref('')
const busy = ref(false)
const plan = ref(null)
const result = ref(null)
const ack = ref('')
const reviewed = ref(false)

const startMode = props.port.port_mode === 'trunk' || props.port.port_mode === 'hybrid' ? 'trunk' : 'access'
const form = reactive({
  mode: startMode,
  access_vlan: startMode === 'access' ? props.port.pvid : null,
  native_vlan: props.port.pvid ?? null,
  allowed: new Set(props.port.tagged_vlans || []),
  save: true,
})

const label = (v) => `${v.id}${v.name ? ` — ${v.name}` : ''}`
const modeLabel = { access: 'Accès', trunk: 'Trunk', hybrid: 'Hybride (accès + VLAN étiquetés)' }
const known = computed(() => new Set(vlans.value.map((v) => v.id)))
const currentText = computed(() => `${modeLabel[props.port.port_mode] || 'inconnu'}${props.port.pvid ? ` · VLAN ${props.port.pvid}` : ''}${(props.port.tagged_vlans || []).length ? ` · étiquetés ${props.port.tagged_vlans.join(', ')}` : ''}`)
const canPreview = computed(() => !busy.value && (form.mode === 'access' ? known.value.has(form.access_vlan) : known.value.has(form.native_vlan)))
const confirmed = computed(() => plan.value && (plan.value.requires_ack ? ack.value === plan.value.ack_phrase : reviewed.value))

function toggle(id) {
  if (form.allowed.has(id)) form.allowed.delete(id)
  else form.allowed.add(id)
}

onMounted(async () => {
  try {
    vlans.value = await get(`/api/v1/devices/${props.device.id}/vlans`)
    if (!vlans.value.length) error.value = 'Les VLAN de cet équipement ne sont pas connus : lancez d’abord une collecte de topologie.'
  } catch (e) {
    error.value = e.message
  } finally {
    loadingVlans.value = false
  }
})

function body() {
  return form.mode === 'access'
    ? { mode: 'access', access_vlan: Number(form.access_vlan), save: form.save }
    : { mode: 'trunk', native_vlan: Number(form.native_vlan), allowed_vlans: [...form.allowed].filter((v) => v !== Number(form.native_vlan)).sort((a, b) => a - b), save: form.save }
}

async function doPreview() {
  error.value = ''
  busy.value = true
  try {
    plan.value = await post(`/api/v1/interfaces/${props.port.id}/port-config/preview`, body())
    ack.value = ''
    reviewed.value = false
    step.value = 'preview'
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}

async function apply() {
  error.value = ''
  busy.value = true
  step.value = 'running'
  try {
    const { job_id: id } = await post(`/api/v1/interfaces/${props.port.id}/port-config/apply`, { plan_id: plan.value.plan_id, acknowledge: ack.value || null })
    const j = await waitJob(id, { tries: 90 })
    result.value = j.result || { ok: false, message: 'Aucune réponse de l’équipement dans le délai imparti.', advice: 'Vérifiez l’état du port sur l’équipement avant de réessayer.', steps: [] }
    step.value = 'result'
    if (result.value.ok) {
      // relit l'état réel du port (SNMP) pour que le tableau affiche la nouvelle configuration
      try {
        const t = await post(`/api/v1/devices/${props.device.id}/topology`)
        await waitJob(t.job_id)
      } catch {
        /* l'état se mettra à jour à la prochaine collecte */
      }
      emit('changed')
    }
  } catch (e) {
    error.value = e.message
    plan.value = null // l'aperçu est à usage unique : il faut le refaire
    step.value = 'form'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :title="`Configurer le port ${port.name} — ${device.name}`" wide @close="emit('close')">
    <ErrorBanner :message="error" />

    <template v-if="step === 'form'">
      <p class="hint">État actuel : <strong>{{ currentText }}</strong>. Seuls les VLAN connus de l’équipement sont proposés. Rien n’est envoyé avant l’aperçu et votre confirmation.</p>
      <form class="pc-form" @submit.prevent="doPreview">
        <fieldset>
          <legend>Mode du port</legend>
          <label class="check opt"><input v-model="form.mode" type="radio" value="access" /><span><strong>Port d’accès</strong><small>Un seul VLAN, non étiqueté : pour un poste, une imprimante, un téléphone.</small></span></label>
          <label class="check opt"><input v-model="form.mode" type="radio" value="trunk" /><span><strong>Trunk</strong><small>Plusieurs VLAN étiquetés + un VLAN natif : pour relier deux équipements réseau.</small></span></label>
        </fieldset>
        <label v-if="form.mode === 'access'">VLAN d’accès
          <select v-model.number="form.access_vlan" required :disabled="loadingVlans"><option :value="null" disabled>Choisir…</option><option v-for="v in vlans" :key="v.id" :value="v.id">{{ label(v) }}</option></select>
        </label>
        <template v-else>
          <label>VLAN natif (PVID)
            <select v-model.number="form.native_vlan" required :disabled="loadingVlans"><option :value="null" disabled>Choisir…</option><option v-for="v in vlans" :key="v.id" :value="v.id">{{ label(v) }}</option></select>
          </label>
          <fieldset>
            <legend>VLAN autorisés (étiquetés)</legend>
            <div class="vlan-grid">
              <label v-for="v in vlans" :key="v.id" class="check"><input type="checkbox" :checked="form.allowed.has(v.id)" :disabled="v.id === form.native_vlan" @change="toggle(v.id)" /> {{ label(v) }}</label>
            </div>
          </fieldset>
        </template>
        <label class="check"><input v-model="form.save" type="checkbox" /> Enregistrer la configuration sur l’équipement (sinon perdue au redémarrage)</label>
        <div class="modal-foot end">
          <button type="button" class="ghost" @click="emit('close')">Annuler</button>
          <button type="submit" :disabled="!canPreview">Aperçu des commandes</button>
        </div>
      </form>
    </template>

    <template v-else-if="step === 'preview' && plan">
      <h3 class="h-sm">Avant → après</h3>
      <p>{{ currentText }} <strong>→</strong> <strong>{{ plan.desired.mode === 'access' ? `Accès · VLAN ${plan.desired.access_vlan}` : `Trunk · natif ${plan.desired.native_vlan}${plan.desired.allowed_vlans.length ? ` · étiquetés ${plan.desired.allowed_vlans.join(', ')}` : ''}` }}</strong></p>
      <ul class="alerts" role="list">
        <li v-for="(a, i) in plan.alerts" :key="i" :class="`alert-${a.level}`">
          <strong>{{ a.level === 'danger' ? 'Danger' : a.level === 'warn' ? 'Attention' : 'Info' }}</strong> — {{ a.text }}
        </li>
      </ul>
      <h3 class="h-sm">Commandes qui seront envoyées par SSH à {{ device.name }}</h3>
      <pre class="config">{{ [...plan.commands, ...plan.save_commands].join('\n') }}</pre>
      <div v-if="plan.requires_ack" class="confirm-danger">
        <p><strong>Confirmation renforcée.</strong> Pour valider, saisissez exactement le nom du port : <code>{{ plan.ack_phrase }}</code></p>
        <input v-model="ack" autocomplete="off" spellcheck="false" :aria-label="`Saisir ${plan.ack_phrase} pour confirmer`" />
      </div>
      <label v-else class="check"><input v-model="reviewed" type="checkbox" /> J’ai relu les commandes ci-dessus.</label>
      <div class="modal-foot end">
        <button type="button" class="ghost" @click="step = 'form'; plan = null">Retour</button>
        <button type="button" :class="plan.requires_ack ? 'danger-solid' : ''" :disabled="!confirmed || busy" @click="apply">Appliquer sur l’équipement</button>
      </div>
    </template>

    <template v-else-if="step === 'running'">
      <p role="status">Application en cours sur {{ device.name }}… ne fermez pas cette fenêtre.</p>
    </template>

    <template v-else-if="step === 'result' && result">
      <p v-if="result.ok" class="notice" role="status"><strong>{{ result.message }}</strong> {{ result.saved ? 'La configuration a été enregistrée sur l’équipement.' : 'La configuration n’a PAS été enregistrée (perdue au redémarrage).' }}</p>
      <div v-else class="error" role="alert"><strong>{{ result.message }}</strong><div v-if="result.advice" class="advice">{{ result.advice }}</div><pre v-if="result.detail" class="config">{{ result.detail }}</pre></div>
      <details v-if="result.steps?.length" open>
        <summary>Déroulé des commandes</summary>
        <ol class="steps"><li v-for="(s, i) in result.steps" :key="i"><code>{{ s.command }}</code><span v-if="s.output" class="hint"> — {{ s.output }}</span></li></ol>
      </details>
      <div class="modal-foot end"><button type="button" @click="emit('close')">Fermer</button></div>
    </template>
  </Modal>
</template>
