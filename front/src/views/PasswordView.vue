<script setup>
// Changement du mot de passe du compte local (imposé à la première connexion). Le serveur applique la politique ; les
// autres sessions du compte sont fermées et une nouvelle session est ouverte.
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import ErrorBanner from '../components/ErrorBanner.vue'
import TotpSection from '../components/TotpSection.vue'
import { get, post } from '../api/client.js'
import { session, setMe } from '../stores/session.js'

const router = useRouter()
const form = reactive({ current: '', next: '', confirm: '' })
const error = ref('')
const busy = ref(false)
const forced = () => session.mustChange

async function submit() {
  error.value = ''
  if (form.next !== form.confirm) {
    error.value = 'Les deux nouveaux mots de passe ne correspondent pas.'
    return
  }
  busy.value = true
  try {
    await post('/api/v1/auth/password', { current_password: form.current, new_password: form.next })
    Object.assign(form, { current: '', next: '', confirm: '' })
    setMe(await get('/api/v1/auth/me'))
    await router.replace('/')
  } catch (e) {
    form.current = ''
    error.value = e.status === 403 ? 'Mot de passe actuel incorrect.' : e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <main :class="forced() ? 'login-page' : 'content'">
    <h1 v-if="!forced()" class="h-sm">Mon compte</h1>
    <section :class="forced() ? 'login-card' : 'card narrow'" aria-labelledby="pw-title">
      <h1 v-if="forced()" id="pw-title" class="h-sm">Définissez votre mot de passe</h1>
      <h2 v-else id="pw-title" class="h-sm">Mot de passe</h2>
      <p v-if="forced()" class="hint">Le mot de passe initial n’est valable qu’une fois : choisissez-en un nouveau pour continuer.</p>
      <p class="hint">12 caractères minimum, sans votre identifiant, sans espace en début ou en fin. Une phrase de passe longue convient très bien.</p>
      <ErrorBanner :message="error" />
      <form autocomplete="off" @submit.prevent="submit">
        <label>Mot de passe actuel<input v-model="form.current" type="password" required maxlength="1024" autocomplete="current-password" /></label>
        <label>Nouveau mot de passe<input v-model="form.next" type="password" required minlength="12" maxlength="128" autocomplete="new-password" /></label>
        <label>Confirmer le nouveau mot de passe<input v-model="form.confirm" type="password" required minlength="12" maxlength="128" autocomplete="new-password" /></label>
        <button type="submit" :disabled="busy">Enregistrer</button>
      </form>
    </section>
    <TotpSection v-if="!forced() && session.user?.source === 'local'" />
  </main>
</template>
