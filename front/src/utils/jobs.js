import { get } from '../api/client.js'

// Interroge un job jusqu'à sa fin (pas de secret dans les résultats de jobs).
export async function waitJob(id, { tries = 60, delayMs = 1000 } = {}) {
  for (let i = 0; i < tries; i++) {
    const j = await get(`/api/v1/jobs/${id}`)
    if (j.status === 'done' || j.status === 'failed') return j
    await new Promise((r) => setTimeout(r, delayMs))
  }
  return { status: 'failed', error_code: 'TIMEOUT', result: null }
}
