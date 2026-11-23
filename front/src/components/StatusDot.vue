<script setup>
import Icon from './Icon.vue'
defineProps({ state: { type: String, default: 'unknown' }, label: { type: String, default: '' } }) // ok | bad | warn | unknown
</script>

<template>
  <span :class="['dot', `dot-${state}`]" :title="label" role="img" :aria-label="label || state">
    <Icon :name="state === 'ok' ? 'ok' : state === 'bad' ? 'bad' : state === 'warn' ? 'warn' : 'alert'" :size="18" />
  </span>
</template>
