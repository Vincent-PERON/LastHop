<script setup>
import PageHeader from '../components/PageHeader.vue'
</script>

<template>
  <div>
    <PageHeader title="Accès refusé" :crumbs="[{ label: 'LastHop' }]" />
    <section class="content"><p>Votre rôle ne permet pas d’ouvrir cette page.</p></section>
  </div>
</template>
