<script setup>
// Fenêtre modale accessible : rôle « dialog », Échap ou clic sur le fond pour fermer, focus piégé puis rendu à l'appelant.
import { ref, onMounted, onBeforeUnmount, nextTick } from 'vue'
import Icon from './Icon.vue'

defineProps({ title: { type: String, required: true }, wide: { type: Boolean, default: false } })
const emit = defineEmits(['close'])
const box = ref(null)
const titleId = `modal-${Math.random().toString(36).slice(2, 8)}`
let opener = null

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function onKey(e) {
  if (e.key === 'Escape') {
    e.stopPropagation()
    emit('close')
  } else if (e.key === 'Tab' && box.value) {
    const items = [...box.value.querySelectorAll(FOCUSABLE)]
    if (!items.length) return
    const first = items[0]
    const last = items[items.length - 1]
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
  }
}

onMounted(async () => {
  opener = document.activeElement
  document.body.classList.add('modal-open')
  document.addEventListener('keydown', onKey)
  await nextTick()
  box.value?.querySelector('.modal-close')?.focus()
})
onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKey)
  document.body.classList.remove('modal-open')
  opener?.focus?.()
})
</script>

<template>
  <div class="modal-backdrop" @mousedown.self="emit('close')">
    <div ref="box" :class="['modal', { wide }]" role="dialog" aria-modal="true" :aria-labelledby="titleId">
      <header class="modal-head">
        <h2 :id="titleId">{{ title }}</h2>
        <button type="button" class="icon-btn modal-close" aria-label="Fermer" @click="emit('close')"><Icon name="bad" :size="22" /></button>
      </header>
      <div class="modal-body"><slot /></div>
      <footer v-if="$slots.footer" class="modal-foot"><slot name="footer" /></footer>
    </div>
  </div>
</template>
