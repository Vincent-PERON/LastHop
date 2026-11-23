<script setup>
// Double authentification TOTP (facultative) du compte local : activation en deux temps (secret puis code de confirmation),
// codes de secours affichés UNE seule fois, désactivation et régénération avec mot de passe + code.
import { reactive, ref } from 'vue'
import ErrorBanner from './ErrorBanner.vue'
import { get, post } from '../api/client.js'
import { session, setMe } from '../stores/session.js'

const step = ref('idle') // idle | password | scan | codes | disable | regen
const form = reactive({ password: '', code: '' })
const setup = ref(null) // { secret, uri, qr } : en mémoire de la page uniquement
const recovery = ref([])
const saved = ref(false)
const copied = ref(false)
const error = ref('')
const busy = ref(false)

const grouped = (s) => (s || '').replace(/(.{4})/g, '$1 ').trim()

async function run(fn) {
  error.value = ''
  busy.value = true
  try {
    await fn()
  } catch (e) {
    error.value = e.status === 403 || e.status === 422 ? e.detail?.detail || e.message : e.message
  } finally {
    busy.value = false
  }
}

const reset = () => {
  Object.assign(form, { password: '', code: '' })
  setup.value = null
  step.value = 'idle'
  error.value = ''
}

const begin = () => run(async () => {
  setup.value = await post('/api/v1/auth/totp/setup', { password: form.password })
  form.password = ''
  step.value = 'scan'
})

const confirm = () => run(async () => {
  const r = await post('/api/v1/auth/totp/enable', { code: form.code })
  recovery.value = r.recovery_codes
  saved.value = false
  setup.value = null
  form.code = ''
  step.value = 'codes'
  setMe(await get('/api/v1/auth/me'))
})

const disable = () => run(async () => {
  await post('/api/v1/auth/totp/disable', { password: form.password, code: form.code })
  reset()
  setMe(await get('/api/v1/auth/me'))
})

const regenerate = () => run(async () => {
  const r = await post('/api/v1/auth/totp/recovery-codes', { password: form.password, code: form.code })
  recovery.value = r.recovery_codes
  saved.value = false
  Object.assign(form, { password: '', code: '' })
  step.value = 'codes'
})

async function copy() {
  try {
    await navigator.clipboard.writeText(recovery.value.join('\n'))
    copied.value = true
  } catch {
    copied.value = false
  }
}

function done() {
  recovery.value = [] // effacés de la mémoire de la page
  reset()
}
</script>

<template>
  <section class="card narrow" aria-labelledby="totp-title">
    <h2 id="totp-title" class="h-sm">Double authentification (TOTP)</h2>
    <ErrorBanner :message="error" />

    <template v-if="step === 'codes'">
      <p class="warn-box" role="alert"><strong>Codes de secours — affichés une seule fois.</strong> Chacun ne sert qu’une fois si vous perdez votre appareil. Conservez-les hors de cet ordinateur (coffre de mots de passe, impression).</p>
      <ul class="recovery"><li v-for="c in recovery" :key="c"><code>{{ c }}</code></li></ul>
      <p><button type="button" class="ghost" @click="copy">{{ copied ? 'Copié' : 'Copier les codes' }}</button></p>
      <label class="check"><input v-model="saved" type="checkbox" /> J’ai conservé ces codes en lieu sûr.</label>
      <button type="button" :disabled="!saved" @click="done">Terminer</button>
    </template>

    <template v-else-if="step === 'scan'">
      <p class="hint">1. Scannez ce QR code avec votre application (FreeOTP, Google Authenticator, Microsoft Authenticator, 1Password…). 2. Saisissez le code à 6 chiffres affiché pour confirmer.</p>
      <img v-if="setup?.qr" class="qr" :src="setup.qr" alt="QR code de configuration TOTP" width="200" height="200" />
      <p class="hint">Saisie manuelle : <code class="secret">{{ grouped(setup?.secret) }}</code></p>
      <form @submit.prevent="confirm">
        <label>Code à 6 chiffres<input v-model="form.code" required maxlength="7" inputmode="numeric" autocomplete="one-time-code" /></label>
        <button type="submit" :disabled="busy">Activer</button>
        <button type="button" class="ghost" @click="reset">Annuler</button>
      </form>
    </template>

    <template v-else-if="session.totp">
      <p><span class="badge badge-ok">activée</span> Un code de votre application sera demandé à chaque connexion locale.</p>
      <form v-if="step === 'disable' || step === 'regen'" autocomplete="off" @submit.prevent="step === 'disable' ? disable() : regenerate()">
        <label>Mot de passe<input v-model="form.password" type="password" required maxlength="1024" autocomplete="current-password" /></label>
        <label>Code (application ou code de secours)<input v-model="form.code" required maxlength="16" autocomplete="one-time-code" /></label>
        <button type="submit" :class="step === 'disable' ? 'danger' : ''" :disabled="busy">{{ step === 'disable' ? 'Désactiver le TOTP' : 'Générer de nouveaux codes' }}</button>
        <button type="button" class="ghost" @click="reset">Annuler</button>
      </form>
      <p v-else>
        <button type="button" class="ghost" @click="step = 'regen'">Régénérer les codes de secours</button>
        <button type="button" class="danger" @click="step = 'disable'">Désactiver</button>
      </p>
    </template>

    <template v-else>
      <p class="hint">Facultative mais recommandée : le compte super admin local est protégé par un mot de passe seul. Activez un second facteur avec une application d’authentification.</p>
      <form v-if="step === 'password'" autocomplete="off" @submit.prevent="begin">
        <label>Confirmez votre mot de passe<input v-model="form.password" type="password" required maxlength="1024" autocomplete="current-password" /></label>
        <button type="submit" :disabled="busy">Continuer</button>
        <button type="button" class="ghost" @click="reset">Annuler</button>
      </form>
      <p v-else><button type="button" @click="step = 'password'">Activer la double authentification</button></p>
    </template>
  </section>
</template>
