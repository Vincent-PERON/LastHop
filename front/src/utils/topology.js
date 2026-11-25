// Conversion du graphe de l'API vers les éléments Cytoscape (fonction pure, testable sans canvas).
export function buildElements(graph) {
  const nodes = (graph.nodes || []).map((n) => ({
    data: { id: n.id, label: n.label || n.name || n.id, role: n.managed === false ? 'external' : n.role || 'unknown', managed: n.managed !== false, vendor: n.vendor, model: n.model },
  }))
  const ids = new Set(nodes.map((n) => n.data.id))
  const edges = (graph.edges || [])
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e) => ({
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        label: [e.source_port, e.target_port].filter(Boolean).join(' ↔ '),
        protocols: (e.protocols || []).join('/'),
      },
    }))
  return [...nodes, ...edges]
}

const ROLE_COLOR_BASE = { distribution: '#0e7490', access: '#047857', unknown: '#6b7280', external: '#9ca3af' }
export const ROLE_COLOR = { core: '#02213d', ...ROLE_COLOR_BASE }

// Palette du graphe selon le thème (Cytoscape dessine sur un canvas : il ne lit pas les variables CSS)
const PALETTE = {
  light: { core: '#02213d', label: '#374151', edge: '#9ca3af', edgeText: '#4b5563', halo: '#ffffff', external: '#6b7280' },
  dark: { core: '#3b82c4', label: '#d0d5dd', edge: '#475467', edgeText: '#98a2b3', halo: '#182133', external: '#98a2b3' },
}

export function styleFor(mode = 'light') {
  const p = PALETTE[mode] || PALETTE.light
  const colors = { ...ROLE_COLOR_BASE, core: p.core }
  return [
    { selector: 'node', style: { label: 'data(label)', 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 4, color: p.label, width: 34, height: 34, 'background-color': (el) => colors[el.data('role')] || colors.unknown, 'border-width': 2, 'border-color': p.halo } },
    { selector: 'node[role = "core"]', style: { shape: 'round-rectangle', width: 46, height: 36 } },
    { selector: 'node[?managed]', style: { 'border-style': 'solid' } },
    { selector: 'node[!managed]', style: { 'border-style': 'dashed', 'border-color': p.external } },
    { selector: 'edge', style: { width: 2, 'line-color': p.edge, label: 'data(label)', 'font-size': 9, color: p.edgeText, 'text-background-color': p.halo, 'text-background-opacity': 0.85, 'text-rotation': 'autorotate', 'curve-style': 'bezier' } },
    { selector: ':selected', style: { 'border-color': '#f59e0b', 'border-width': 4, 'line-color': '#f59e0b' } },
  ]
}

export const STYLE = styleFor('light')
