import { createApp } from 'vue'
import App from './App.vue'
import { router } from './router.js'
import { api, setUnauthorizedHandler } from './api/client.js'
import { setMe, clearSession } from './stores/session.js'
import './styles.css'

// Session expirée en cours d'utilisation : retour à la page de connexion (le chemin courant est conservé)
setUnauthorizedHandler(() => {
  clearSession()
  const here = router.currentRoute.value
  if (here.name !== 'login') router.push({ name: 'login', query: { next: here.fullPath } })
})

async function boot() {
  try {
    setMe(await api('GET', '/api/v1/auth/me', { quiet401: true }))
  } catch {
    clearSession() // non connecté (401) ou API injoignable : la page de connexion s'affiche
  }
  createApp(App).use(router).mount('#app')
}

boot()
