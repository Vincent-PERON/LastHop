<script setup>
// Choix du thème : clair, sombre ou système (suit le système d'exploitation).
import Dropdown from './Dropdown.vue'
import Icon from './Icon.vue'
import { theme, setTheme } from '../stores/theme.js'

const OPTIONS = [
  { mode: 'light', label: 'Clair', icon: 'sun' },
  { mode: 'dark', label: 'Sombre', icon: 'moon' },
  { mode: 'system', label: 'Système', icon: 'monitor' },
]
const current = () => (OPTIONS.find((o) => o.mode === theme.mode) || OPTIONS[2]).icon
</script>

<template>
  <Dropdown label="Choisir le thème">
    <template #trigger><Icon :name="current()" :size="20" /></template>
    <button v-for="o in OPTIONS" :key="o.mode" type="button" class="dd-item" role="menuitemradio" :aria-checked="theme.mode === o.mode" @click="setTheme(o.mode)">
      <Icon :name="o.icon" :size="18" /> <span class="grow">{{ o.label }}</span>
      <Icon v-if="theme.mode === o.mode" name="check" :size="16" />
    </button>
  </Dropdown>
</template>
