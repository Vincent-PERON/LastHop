// Flux SSE de la localisation en direct (même origine : le cookie de session accompagne la requête).
import { post } from './client.js'

export const EVENT_TYPES = ['started', 'arp_resolving', 'arp_resolved', 'fdb_querying', 'device_queried', 'hop', 'located', 'failed', 'done', 'auth_expired']

export async function startRealtime(query, siteId) {
  return post('/api/v1/realtime', { query, ...(siteId ? { site_id: siteId } : {}) })
}

// Ouvre le flux et appelle onEvent({type, data}). Retourne { close }.
export function openStream(eventsUrl, onEvent, onBroken) {
  const es = new EventSource(eventsUrl, { withCredentials: false })
  let finished = false
  for (const type of EVENT_TYPES) {
    es.addEventListener(type, (e) => {
      let data = {}
      try {
        data = JSON.parse(e.data)
      } catch {
        /* événement sans données */
      }
      if (type === 'done' || type === 'auth_expired') {
        finished = true
        es.close()
      }
      onEvent({ type, data })
    })
  }
  es.onerror = () => {
    // EventSource se reconnecte seul (avec Last-Event-ID) tant que le flux n'est pas terminé ; on signale la rupture définitive
    if (!finished && es.readyState === 2) onBroken?.()
  }
  return { close: () => es.close() }
}
