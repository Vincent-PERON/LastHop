<script setup>
// Pagination « 1 2 3 … » + « Affichage de x à y sur N » + nombre de lignes par page.
import { computed } from 'vue'

const props = defineProps({
  total: { type: Number, default: 0 },
  offset: { type: Number, default: 0 },
  limit: { type: Number, default: 25 },
  sizes: { type: Array, default: () => [10, 25, 50, 100] },
})
const emit = defineEmits(['change', 'limit'])

const pages = computed(() => Math.max(1, Math.ceil(props.total / props.limit)))
const current = computed(() => Math.floor(props.offset / props.limit) + 1)
const from = computed(() => (props.total ? props.offset + 1 : 0))
const to = computed(() => Math.min(props.offset + props.limit, props.total))
const shown = computed(() => {
  const n = pages.value
  const set = new Set([1, n, current.value - 1, current.value, current.value + 1])
  const list = [...set].filter((p) => p >= 1 && p <= n).sort((a, b) => a - b)
  return list.flatMap((p, i) => (i && p - list[i - 1] > 1 ? ['…', p] : [p]))
})
const go = (p) => emit('change', (p - 1) * props.limit)
</script>

<template>
  <nav class="pager" aria-label="Pagination">
    <div class="pages">
      <button type="button" aria-label="Page précédente" :disabled="current <= 1" @click="go(current - 1)">‹</button>
      <template v-for="(p, i) in shown" :key="i">
        <span v-if="p === '…'" class="gap">…</span>
        <button v-else type="button" :class="{ on: p === current }" :aria-current="p === current ? 'page' : undefined" @click="go(p)">{{ p }}</button>
      </template>
      <button type="button" aria-label="Page suivante" :disabled="current >= pages" @click="go(current + 1)">›</button>
    </div>
    <span class="count">Affichage de {{ from }} à {{ to }} sur {{ total }} entrée(s)</span>
    <div class="sizes" aria-label="Lignes par page">
      <button v-for="s in sizes" :key="s" type="button" :class="{ on: s === limit }" @click="emit('limit', s)">{{ s }}</button>
    </div>
  </nav>
</template>
