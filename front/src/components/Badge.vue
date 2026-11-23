<script setup>
defineProps({ kind: { type: String, default: 'neutral' } })
</script>

<template><span :class="['badge', `badge-${kind}`]"><slot /></span></template>
