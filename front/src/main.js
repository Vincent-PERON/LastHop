import { createApp } from 'vue'
import App from './App.vue'
import { router } from './router.js'
import { get, setUnauthorizedHandler } from './api/client.js'
import { setMe, clearSession, loginUrl } from './stores/session.js'
import './styles.css'

setUnauthorizedHandler(() => {
  clearSession()
  window.location.assign(loginUrl(window.location.pathname + window.location.search))
})

async function boot() {
  try {
    setMe(await get('/api/v1/auth/me'))
  } catch {
    return // 401 : redirection déjà déclenchée ; autre erreur : l'application affichera l'état « non connecté »
  }
  createApp(App).use(router).mount('#app')
}

boot()
