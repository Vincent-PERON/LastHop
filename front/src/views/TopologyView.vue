<script setup>
import PageHeader from '../components/PageHeader.vue'
import { ref, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { RouterLink } from 'vue-router'
import cytoscape from 'cytoscape'
import ErrorBanner from '../components/ErrorBanner.vue'
import { get } from '../api/client.js'
import { can } from '../stores/session.js'
import { buildElements, STYLE } from '../utils/topology.js'

const el = ref(null)
const sites = ref([])
const siteId = ref('')
const unmanaged = ref(false)
const error = ref('')
const selected = ref(null)
const counts = ref({ nodes: 0, edges: 0 })
let cy = null

// Cytoscape tente d'injecter une balise <style> (interdite par notre CSP « style-src 'self' », que nous ne relâchons pas) :
// la règle équivalente est dans styles.css ; on pose le marqueur qu'il cherche pour qu'il n'essaie pas.
const CY_STYLE_ID = '__________cytoscape_stylesheet'
function markCytoscapeStyle() {
  if (!document.getElementById(CY_STYLE_ID)) {
    const m = document.createElement('meta')
    m.id = CY_STYLE_ID
    document.head.appendChild(m)
  }
}

function layout() {
  const roots = cy.nodes('[role = "core"]')
  cy.layout({ name: 'breadthfirst', directed: false, roots: roots.length ? roots : undefined, padding: 30, spacingFactor: 1.3, animate: false }).run()
}

async function load() {
  error.value = ''
  selected.value = null
  try {
    const g = await get('/api/v1/topology/graph', { site_id: siteId.value, include_unmanaged: unmanaged.value || undefined })
    const elements = buildElements(g)
    counts.value = { nodes: g.nodes.length, edges: g.edges.length }
    await nextTick()
    cy?.destroy()
    markCytoscapeStyle()
    cy = cytoscape({ container: el.value, elements, style: STYLE, minZoom: 0.2, maxZoom: 3 })
    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data()
      selected.value = d.managed ? { id: d.id, label: d.label, role: d.role, vendor: d.vendor, model: d.model } : { label: d.label, role: 'externe (non géré)' }
    })
    cy.on('tap', (evt) => {
      if (evt.target === cy) selected.value = null
    })
    layout()
  } catch (e) {
    error.value = e.message
  }
}

onMounted(async () => {
  try {
    sites.value = await get('/api/v1/sites')
  } catch {
    /* sans filtre de site */
  }
  load()
})
onBeforeUnmount(() => cy?.destroy())
watch([siteId, unmanaged], load)
</script>

<template>
  <div>
    <PageHeader title="Topologie L2" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content">
    <div class="filters">
      <label>Site
        <select v-model="siteId"><option value="">Tous</option><option v-for="s in sites" :key="s.id" :value="s.id">{{ s.name }}</option></select>
      </label>
      <label class="check"><input v-model="unmanaged" type="checkbox" /> Voisins non gérés</label>
      <button type="button" @click="cy && layout()">Réorganiser</button>
      <button type="button" @click="cy && cy.fit(undefined, 30)">Ajuster</button>
      <span class="hint">{{ counts.nodes }} équipement(s), {{ counts.edges }} liaison(s)</span>
    </div>
    <ErrorBanner :message="error" />
    <ul class="legend" aria-label="Légende">
      <li><i class="dot dot-core"></i> cœur</li>
      <li><i class="dot dot-distribution"></i> distribution</li>
      <li><i class="dot dot-access"></i> accès</li>
      <li><i class="dot dot-external"></i> non géré</li>
    </ul>
    <div ref="el" class="graph" role="img" aria-label="Graphe de la topologie"></div>
    <aside v-if="selected" class="panel" aria-label="Équipement sélectionné">
      <h2>{{ selected.label }}</h2>
      <p>{{ selected.role }} <template v-if="selected.vendor">— {{ selected.vendor }} {{ selected.model }}</template></p>
      <p v-if="selected.id && can('inventory:read')"><RouterLink :to="{ name: 'device', params: { id: selected.id } }">Voir les ports</RouterLink></p>
    </aside>
    </section>
  </div>
</template>
