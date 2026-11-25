<script setup>
// Menu déroulant accessible : bouton déclencheur (aria-expanded), fermeture par Échap / clic extérieur, focus rendu au bouton.
import { ref, onMounted, onBeforeUnmount } from 'vue'

defineProps({ label: { type: String, required: true }, buttonClass: { type: String, default: 'icon-btn' } })
const open = ref(false)
const root = ref(null)
const btn = ref(null)

function close(returnFocus = false) {
  open.value = false
  if (returnFocus) btn.value?.focus()
}
function onDoc(e) {
  if (open.value && root.value && !root.value.contains(e.target)) close()
}
function onKey(e) {
  if (e.key === 'Escape' && open.value) {
    e.stopPropagation()
    close(true)
  }
}
onMounted(() => {
  document.addEventListener('mousedown', onDoc)
  document.addEventListener('keydown', onKey)
})
onBeforeUnmount(() => {
  document.removeEventListener('mousedown', onDoc)
  document.removeEventListener('keydown', onKey)
})
defineExpose({ close })
</script>

<template>
  <div ref="root" class="dd">
    <button ref="btn" type="button" :class="buttonClass" :aria-label="label" aria-haspopup="true" :aria-expanded="open" @click="open = !open">
      <slot name="trigger" />
    </button>
    <div v-if="open" class="dd-menu" role="menu" :aria-label="label" @click="close()">
      <slot />
    </div>
  </div>
</template>
