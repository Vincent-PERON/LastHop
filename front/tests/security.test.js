import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f)
    return statSync(p).isDirectory() ? walk(p) : [p]
  })
}
const SRC = walk('src').filter((f) => /\.(js|vue)$/.test(f))
const read = (f) => readFileSync(f, 'utf8')

describe('règles de sécurité du code front', () => {
  it('aucun rendu de HTML brut ni exécution dynamique', () => {
    const bad = /v-html|innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(|dangerouslySetInnerHTML/
    expect(SRC.filter((f) => bad.test(read(f)))).toEqual([])
  })

  it('aucun stockage navigateur (les jetons restent dans des cookies HttpOnly, jamais en JS)', () => {
    // Seule exception : le CHOIX de thème (« light | dark | system ») dans stores/theme.js, sous une clé unique, sans donnée sensible
    const users = SRC.filter((f) => /localStorage|sessionStorage|indexedDB|document\.cookie/.test(read(f)))
    expect(users).toEqual(['src/stores/theme.js'])
    expect(/sessionStorage|indexedDB|document\.cookie/.test(read('src/stores/theme.js'))).toBe(false)
    expect([...read('src/stores/theme.js').matchAll(/(?:get|set)Item\(([^,)]+)/g)].map((m) => m[1]).every((k) => k === 'KEY')).toBe(true)
    expect(read('src/stores/theme.js')).toMatch(/const KEY = 'lasthop-theme'/)
  })

  it('aucun secret, URL externe ni CDN en dur', () => {
    const bad = /https?:\/\/(?!localhost|127\.0\.0\.1)/
    expect(SRC.filter((f) => bad.test(read(f).replace(/\/\/.*$/gm, '')))).toEqual([])
  })

  it('index.html sans script ni style en ligne (CSP stricte sans unsafe-inline)', () => {
    const html = read('index.html')
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/)
    expect(html).not.toMatch(/\son\w+=|style=/)
  })

  it('aucun attribut style en ligne dans les gabarits', () => {
    expect(SRC.filter((f) => f.endsWith('.vue') && /\sstyle="/.test(read(f)))).toEqual([])
  })

  it('dépendances épinglées (versions exactes, pas de ^ ni ~)', () => {
    const pkg = JSON.parse(read('package.json'))
    for (const [name, v] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
      expect(v, name).toMatch(/^\d+\.\d+\.\d+$/)
    }
  })
})
