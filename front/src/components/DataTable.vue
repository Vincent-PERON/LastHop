<script setup>
// Tableau basé sur TanStack Table (v9) : pagination/tri pilotés par le serveur, rendu texte uniquement (jamais de HTML brut).
import { toRef } from 'vue'
import { useTable, tableFeatures, FlexRender } from '@tanstack/vue-table'

const props = defineProps({
  columns: { type: Array, required: true },
  data: { type: Array, default: () => [] },
  rowKey: { type: String, default: 'id' },
  loading: { type: Boolean, default: false },
  empty: { type: String, default: 'Aucun résultat.' },
  clickable: { type: Boolean, default: false },
})
const emit = defineEmits(['row-click'])

const table = useTable({
  features: tableFeatures({}),
  columns: props.columns,
  data: toRef(props, 'data'),
  getRowId: (row, index) => String(row[props.rowKey] ?? index),
})
</script>

<template>
  <div class="table-wrap" :aria-busy="loading">
    <table>
      <thead>
        <tr v-for="hg in table.getHeaderGroups()" :key="hg.id">
          <th v-for="h in hg.headers" :key="h.id" scope="col">
            <FlexRender v-if="!h.isPlaceholder" :render="h.column.columnDef.header" :props="h.getContext()" />
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in table.getRowModel().rows"
          :key="row.id"
          :class="{ clickable }"
          :tabindex="clickable ? 0 : undefined"
          @click="clickable && emit('row-click', row.original)"
          @keydown.enter="clickable && emit('row-click', row.original)"
        >
          <td v-for="cell in row.getAllCells()" :key="cell.id" :data-col="cell.column.id">
            <slot :name="`cell-${cell.column.id}`" :row="row.original" :value="cell.getValue()">{{ cell.getValue() ?? '—' }}</slot>
          </td>
        </tr>
        <tr v-if="!loading && table.getRowModel().rows.length === 0">
          <td class="empty" :colspan="columns.length">{{ empty }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
