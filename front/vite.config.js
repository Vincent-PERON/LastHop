import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    target: 'es2022',
    sourcemap: false,
    modulePreload: { polyfill: false }, // aucun script injecté en ligne : compatible avec une CSP sans 'unsafe-inline'
  },
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8787', changeOrigin: false } },
  },
  test: { environment: 'jsdom', include: ['tests/**/*.test.js'] },
})
