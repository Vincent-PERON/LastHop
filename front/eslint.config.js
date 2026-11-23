import js from '@eslint/js'
import globals from 'globals'
import pluginVue from 'eslint-plugin-vue'

export default [
  js.configs.recommended,
  ...pluginVue.configs['flat/recommended'],
  {
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      'vue/no-v-html': 'error', // jamais de HTML brut : les données d'équipements sont non fiables
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'vue/multi-word-component-names': 'off',
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-self-closing': 'off',
      'vue/html-closing-bracket-newline': 'off',
      'vue/html-indent': 'off',
      'vue/first-attribute-linebreak': 'off',
      'vue/attributes-order': 'off',
    },
  },
  { ignores: ['dist/**', 'node_modules/**'] },
]
