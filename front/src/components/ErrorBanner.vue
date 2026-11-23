<script setup>
defineProps({ message: { type: String, default: '' } })
</script>

<template><p v-if="message" class="error" role="alert">{{ message }}</p></template>
