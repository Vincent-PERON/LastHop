<script setup>
// Grille de ports : une tuile par port ; barre verte (up) / rouge (down) ; liseré orange = uplink.
import { computed } from 'vue'
const props = defineProps({ ports: { type: Array, default: () => [] }, selected: { type: String, default: '' } })
const emit = defineEmits(['select'])
const short = (n) => (n.length > 9 ? '…' + n.slice(-8) : n)
const tiles = computed(() => props.ports.map((p) => ({ ...p, short: short(p.name), up: p.oper_status === 1 })))
</script>

<template>
  <div class="port-grid" role="list" aria-label="Ports de l’équipement">
    <button
      v-for="p in tiles"
      :key="p.id"
      type="button"
      role="listitem"
      :class="['tile', p.up ? 'up' : 'down', { uplink: p.role === 'uplink', sel: selected === p.id }]"
      :title="`${p.name} — ${p.up ? 'up' : 'down'} — ${p.role === 'uplink' ? 'uplink' : 'accès'}${p.alias ? ' — ' + p.alias : ''}`"
      @click="emit('select', p)"
    >
{{ p.short }}
</button>
    <p v-if="!ports.length" class="hint">Aucun port : lancez une collecte de topologie.</p>
  </div>
</template>
