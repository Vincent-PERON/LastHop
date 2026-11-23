<script setup>
// Compteur de ports « up (vert) / down (orange) » : deux cases à largeur fixe, lisibles aussi sans couleur (chiffres).
defineProps({ up: { type: Number, default: 0 }, down: { type: Number, default: 0 } })
</script>

<template>
  <span class="portbar" :title="`${up} ports up, ${down} ports down`">
    <span class="pb up">{{ up }}</span><span class="pb down">{{ down }}</span>
  </span>
</template>
