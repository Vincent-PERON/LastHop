<script setup>
// Page de connexion : compte local (super admin), annuaires LDAP (formulaire) et fournisseurs OIDC (boutons : Keycloak,
// Entra ID, Google Workspace…). Aucun mot de passe n'est conservé : le champ est vidé dès l'envoi ; la session est un
// cookie HttpOnly posé par le serveur.
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import ErrorBanner from '../components/ErrorBanner.vue'
import Icon from '../components/Icon.vue'
import ThemeMenu from '../components/ThemeMenu.vue'
import { get, post } from '../api/client.js'
import { setMe, safeNext, oidcLoginUrl } from '../stores/session.js'

const route = useRoute()
const router = useRouter()
const providers = ref([])
const loadError = ref('')
const error = ref('')
const busy = ref(false)
const target = ref('local') // « local » ou l'identifiant d'un annuaire LDAP
const form = reactive({ username: '', password: '' })
// 2e étape (TOTP) : le défi reste en mémoire de la page uniquement ; il expire côté serveur au bout de 5 minutes
const challenge = ref('')
const code = ref('')
const useRecovery = ref(false)

const ldap = computed(() => providers.value.filter((p) => p.kind === 'ldap'))
const oidc = computed(() => providers.value.filter((p) => p.kind === 'oidc'))
const next = () => safeNext(route.query.next)

onMounted(async () => {
  try {
    providers.value = (await get('/api/v1/auth/providers')).providers
  } catch (e) {
    loadError.value = e.message
  }
})

async function submit() {
  error.value = ''
  busy.value = true
  const url = target.value === 'local' ? '/api/v1/auth/local/login' : `/api/v1/auth/ldap/${encodeURIComponent(target.value)}/login`
  try {
    const r = await post(url, { username: form.username.trim(), password: form.password }, { quiet401: true })
    form.password = ''
    if (r?.status === 'totp_required') {
      challenge.value = r.challenge
      return
    }
    await finish(r)
  } catch (e) {
    form.password = ''
    error.value =
      e.status === 401 ? 'Identifiant ou mot de passe incorrect.'
      : e.status === 403 ? 'Ce compte n’est pas autorisé à utiliser LastHop (aucun groupe correspondant).'
      : e.status === 429 ? 'Trop de tentatives : réessayez dans quelques minutes.'
      : e.message
  } finally {
    busy.value = false
  }
}

async function finish(r) {
  setMe(await get('/api/v1/auth/me'))
  await router.replace(r?.must_change_password ? { name: 'password' } : next())
}

async function submitCode() {
  error.value = ''
  busy.value = true
  try {
    const r = await post('/api/v1/auth/local/totp', { challenge: challenge.value, code: code.value.trim() }, { quiet401: true })
    code.value = ''
    challenge.value = ''
    await finish(r)
  } catch (e) {
    code.value = ''
    error.value = e.status === 401 ? 'Code incorrect, expiré ou compte verrouillé. Recommencez la connexion si le problème persiste.'
      : e.status === 429 ? 'Trop de tentatives : réessayez dans quelques minutes.' : e.message
  } finally {
    busy.value = false
  }
}

function backToPassword() {
  challenge.value = ''
  code.value = ''
  error.value = ''
  useRecovery.value = false
}

function viaOidc(p) {
  window.location.assign(oidcLoginUrl(p.id, next()))
}
</script>

<template>
  <main class="login-page">
    <div class="login-theme"><ThemeMenu /></div>
    <section class="login-card" aria-labelledby="login-title">
      <div class="login-brand"><span class="mark">L</span><h1 id="login-title">Last<span>Hop</span></h1></div>
      <p class="hint">Connectez-vous pour rechercher une adresse IP ou MAC et consulter la topologie.</p>
      <ErrorBanner :message="loadError" />
      <ErrorBanner :message="error" />
      <form v-if="challenge" autocomplete="off" @submit.prevent="submitCode">
        <p class="hint">Mot de passe accepté. Saisissez le code à 6 chiffres de votre application d’authentification, ou un code de secours.</p>
        <label>{{ useRecovery ? 'Code de secours' : 'Code à 6 chiffres' }}
          <input v-model="code" required :maxlength="useRecovery ? 16 : 7" :inputmode="useRecovery ? 'text' : 'numeric'" autocomplete="one-time-code" autofocus />
        </label>
        <button type="submit" :disabled="busy">{{ busy ? 'Vérification…' : 'Valider' }}</button>
        <button type="button" class="ghost" @click="useRecovery = !useRecovery; code = ''">{{ useRecovery ? 'Utiliser le code de mon application' : 'Utiliser un code de secours' }}</button>
        <button type="button" class="ghost" @click="backToPassword">Retour</button>
      </form>
      <form v-else autocomplete="on" @submit.prevent="submit">
        <label v-if="ldap.length">Compte
          <select v-model="target" aria-label="Type de compte">
            <option value="local">Compte local (super admin)</option>
            <option v-for="p in ldap" :key="p.id" :value="p.id">{{ p.name }} (annuaire)</option>
          </select>
        </label>
        <label>Identifiant<input v-model="form.username" required maxlength="128" autocomplete="username" pattern="[A-Za-z0-9._@\-]+" autofocus /></label>
        <label>Mot de passe<input v-model="form.password" type="password" required maxlength="512" autocomplete="current-password" /></label>
        <button type="submit" :disabled="busy">{{ busy ? 'Connexion…' : 'Se connecter' }}</button>
      </form>
      <template v-if="oidc.length && !challenge">
        <p class="login-sep"><span>ou</span></p>
        <button v-for="p in oidc" :key="p.id" type="button" class="ghost provider-btn" @click="viaOidc(p)">
          <Icon name="shield" :size="18" /> Se connecter avec {{ p.name }}
        </button>
      </template>
    </section>
  </main>
</template>
