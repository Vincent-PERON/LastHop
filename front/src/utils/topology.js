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

export const ROLE_COLOR = { core: '#02213d', distribution: '#0e7490', access: '#047857', unknown: '#6b7280', external: '#9ca3af' }

export const STYLE = [
  { selector: 'node', style: { label: 'data(label)', 'font-size': 11, 'text-valign': 'bottom', 'text-margin-y': 4, color: '#374151', width: 34, height: 34, 'background-color': (el) => ROLE_COLOR[el.data('role')] || ROLE_COLOR.unknown, 'border-width': 2, 'border-color': '#ffffff' } },
  { selector: 'node[role = "core"]', style: { shape: 'round-rectangle', width: 46, height: 36 } },
  { selector: 'node[?managed]', style: { 'border-style': 'solid' } },
  { selector: 'node[!managed]', style: { 'border-style': 'dashed', 'border-color': '#6b7280' } },
  { selector: 'edge', style: { width: 2, 'line-color': '#9ca3af', label: 'data(label)', 'font-size': 9, color: '#4b5563', 'text-background-color': '#ffffff', 'text-background-opacity': 0.85, 'text-rotation': 'autorotate', 'curve-style': 'bezier' } },
  { selector: ':selected', style: { 'border-color': '#f59e0b', 'border-width': 4, 'line-color': '#f59e0b' } },
]
