<script setup>
// Bandeau bleu : fil d'Ariane, titre, compteurs à droite et onglets (style « console d'administration »).
import { RouterLink } from 'vue-router'
import Icon from './Icon.vue'

defineProps({
  title: { type: String, required: true },
  crumbs: { type: Array, default: () => [] }, // [{ label, to? }]
  kpis: { type: Array, default: () => [] }, // [{ value, label }]
  tabs: { type: Array, default: () => [] }, // [{ label, to }]
})
</script>

<template>
  <header class="band">
    <div class="band-top">
      <div class="band-title">
        <nav class="crumbs" aria-label="Fil d’Ariane">
          <template v-for="(c, i) in crumbs" :key="i">
            <RouterLink v-if="c.to" :to="c.to">{{ c.label }}</RouterLink>
            <span v-else>{{ c.label }}</span>
            <Icon name="chevron" :size="14" />
          </template>
          <h1>{{ title }}</h1>
        </nav>
        <slot name="actions" />
      </div>
      <dl v-if="kpis.length" class="kpis">
        <div v-for="k in kpis" :key="k.label" class="kpi">
          <dd>{{ k.value }}</dd>
          <dt>{{ k.label }}</dt>
        </div>
      </dl>
    </div>
    <nav v-if="tabs.length" class="tabs" aria-label="Sections">
      <RouterLink v-for="t in tabs" :key="t.label" :to="t.to" :class="{ active: t.active }">{{ t.label }}</RouterLink>
    </nav>
  </header>
</template>
