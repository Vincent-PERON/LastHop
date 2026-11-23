<script setup>
// Création / modification d'un fournisseur d'identité. Les secrets (client_secret, mot de passe de service LDAP) sont saisis
// ici, envoyés une fois, chiffrés côté serveur et jamais réaffichés (champ vide en modification = secret inchangé).
import { reactive, ref, computed } from 'vue'
import Modal from './Modal.vue'
import ErrorBanner from './ErrorBanner.vue'
import { post, put } from '../api/client.js'
import { PRESETS } from '../utils/format.js'

const props = defineProps({ provider: { type: Object, default: null } })
const emit = defineEmits(['saved', 'close'])
const editing = Boolean(props.provider)
const p = props.provider
const c = p?.config || {}

const form = reactive({
  preset: p?.preset || 'keycloak',
  name: p?.name || '',
  enabled: p?.enabled || false,
  secret: '',
  clear_secret: false,
  default_role: p?.default_role || '',
  rows: Object.entries(p?.role_map || {}).map(([group, role]) => ({ group, role })),
  // OIDC
  issuer: c.issuer || '',
  client_id: c.client_id || '',
  scopes: c.scopes || 'openid profile email',
  groups_claim: c.groups_claim || 'groups',
  allowed_domains: (c.allowed_domains || []).join(', '),
  require_email_verified: c.require_email_verified ?? false,
  required_acr: c.required_acr || '',
  // LDAP
  url: c.url || '',
  mode: c.url?.startsWith('ldaps') ? 'ldaps' : c.starttls ? 'starttls' : c.insecure ? 'insecure' : 'ldaps',
  ack: Boolean(c.insecure),
  ca_pem: c.ca_pem || '',
  bind_dn: c.bind_dn || '',
  bind_dn_template: c.bind_dn_template || '',
  user_base: c.user_base || '',
  user_filter: c.user_filter || '(uid={username})',
  uid_attr: c.uid_attr ?? '',
  display_attr: c.display_attr || 'cn',
  mail_attr: c.mail_attr || 'mail',
  group_attr: c.group_attr || 'memberOf',
  group_base: c.group_base || '',
  group_filter: c.group_filter || '(member={user_dn})',
})
if (!form.rows.length) form.rows.push({ group: '', role: 'viewer' })

const meta = computed(() => PRESETS[form.preset] || PRESETS.generic)
const isLdap = computed(() => meta.value.kind === 'ldap')
const kind = computed(() => (isLdap.value ? 'ldap' : 'oidc'))
const noGroups = computed(() => form.preset === 'google')
const error = ref('')
const busy = ref(false)

function onPreset() {
  if (isLdap.value) {
    form.user_filter = meta.value.filter
    form.uid_attr = meta.value.uid
    form.display_attr = meta.value.display
  }
}

function config() {
  if (!isLdap.value) {
    return {
      issuer: form.issuer.trim(),
      client_id: form.client_id.trim(),
      scopes: form.scopes.trim(),
      groups_claim: form.groups_claim.trim(),
      allowed_domains: form.allowed_domains.split(/[\s,;]+/).filter(Boolean),
      require_email_verified: form.require_email_verified,
      required_acr: form.required_acr.trim() || null,
    }
  }
  return {
    url: form.url.trim(),
    starttls: form.mode === 'starttls',
    insecure: form.mode === 'insecure' && form.ack,
    ca_pem: form.ca_pem.trim() || null,
    bind_dn: form.bind_dn.trim() || null,
    bind_dn_template: form.bind_dn_template.trim() || null,
    user_base: form.user_base.trim(),
    user_filter: form.user_filter.trim(),
    uid_attr: form.uid_attr.trim(),
    display_attr: form.display_attr.trim(),
    mail_attr: form.mail_attr.trim(),
    group_attr: form.group_attr.trim(),
    group_base: form.group_base.trim() || null,
    group_filter: form.group_filter.trim(),
  }
}

async function save() {
  error.value = ''
  if (isLdap.value && form.mode === 'insecure' && !form.ack) {
    error.value = 'Cochez la reconnaissance : les mots de passe circuleront en clair sur le réseau.'
    return
  }
  const role_map = Object.fromEntries(form.rows.filter((r) => r.group.trim()).map((r) => [r.group.trim(), r.role]))
  busy.value = true
  try {
    const body = { name: form.name.trim(), preset: form.preset, enabled: form.enabled, config: config(), role_map }
    if (form.secret) body.secret = form.secret
    if (form.default_role) body.default_role = form.default_role
    let saved
    if (editing) {
      if (!form.default_role && p.default_role) body.clear_default_role = true
      if (form.clear_secret && !form.secret) body.clear_secret = true
      saved = await put(`/api/v1/auth-providers/${p.id}`, body)
    } else {
      saved = await post('/api/v1/auth-providers', { kind: kind.value, ...body })
    }
    form.secret = '' // effacé de la mémoire de la page dès l'enregistrement
    emit('saved', saved)
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :title="editing ? `Modifier « ${provider.name} »` : 'Ajouter un fournisseur d’identité'" wide @close="emit('close')">
    <form class="auth-form" autocomplete="off" @submit.prevent="save">
      <ErrorBanner :message="error" />
      <div class="form-grid">
        <label>Type
          <select v-model="form.preset" :disabled="editing" @change="onPreset">
            <optgroup label="OpenID Connect"><option v-for="k in ['keycloak', 'entra', 'google', 'generic']" :key="k" :value="k">{{ PRESETS[k].label }}</option></optgroup>
            <optgroup label="Annuaire direct"><option v-for="k in ['ad', 'ldap']" :key="k" :value="k">{{ PRESETS[k].label }}</option></optgroup>
          </select>
        </label>
        <label>Nom affiché<input v-model.trim="form.name" required maxlength="100" /></label>
        <label class="check"><input v-model="form.enabled" type="checkbox" /> Activé (visible sur la page de connexion)</label>
      </div>
      <p v-if="meta.hint" class="hint">{{ meta.hint }}</p>

      <template v-if="!isLdap">
        <p v-if="provider?.redirect_uri" class="hint">URL de redirection à déclarer chez le fournisseur : <code>{{ provider.redirect_uri }}</code></p>
        <p v-else class="hint">L’URL de redirection à déclarer chez le fournisseur sera affichée après l’enregistrement (<code>…/api/v1/auth/oidc/callback</code>).</p>
        <div class="form-grid">
          <label>Émetteur (issuer)<input v-model.trim="form.issuer" required maxlength="512" :placeholder="meta.issuer" /></label>
          <label>Identifiant client (client_id)<input v-model.trim="form.client_id" required maxlength="256" /></label>
          <label>Secret du client
            <input v-model="form.secret" type="password" maxlength="4096" autocomplete="new-password" :placeholder="editing && provider.has_secret ? '•••••• (inchangé si vide)' : ''" />
          </label>
          <label v-if="!noGroups">Claim des groupes<input v-model.trim="form.groups_claim" maxlength="64" /></label>
          <label>Domaines autorisés<input v-model="form.allowed_domains" :required="noGroups" placeholder="corp.example, filiale.example" /></label>
          <label class="check"><input v-model="form.require_email_verified" type="checkbox" :disabled="noGroups" /> Exiger un e-mail vérifié</label>
        </div>
        <details>
<summary>Options avancées</summary>
          <div class="form-grid">
            <label>Scopes<input v-model.trim="form.scopes" maxlength="200" /></label>
            <label>ACR exigé (ex. mfa)<input v-model.trim="form.required_acr" maxlength="64" /></label>
          </div>
        </details>
      </template>

      <template v-else>
        <fieldset>
          <legend>Connexion à l’annuaire</legend>
          <div class="form-grid">
            <label>URL<input v-model.trim="form.url" required maxlength="300" :placeholder="form.mode === 'ldaps' ? 'ldaps://ldap.corp.example:636' : 'ldap://ldap.corp.example:389'" /></label>
            <label>Chiffrement
              <select v-model="form.mode">
                <option value="ldaps">LDAPS (recommandé)</option>
                <option value="starttls">LDAP + StartTLS</option>
                <option value="insecure">Aucun (non recommandé)</option>
              </select>
            </label>
          </div>
          <p v-if="form.mode === 'insecure'" class="warn-box" role="alert">
            <strong>Connexion non chiffrée :</strong> les mots de passe des utilisateurs circuleront en clair sur le réseau. À réserver à un laboratoire isolé.
            <label class="check"><input v-model="form.ack" type="checkbox" /> J’ai compris le risque et je l’accepte.</label>
          </p>
          <label v-else>Autorité de certification (PEM, facultatif : sinon autorités du système)<textarea v-model="form.ca_pem" rows="3" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
          <div class="form-grid">
            <label>Compte de service (DN) — lecture seule<input v-model.trim="form.bind_dn" maxlength="512" placeholder="CN=svc-lasthop,OU=Service,DC=corp,DC=local" /></label>
            <label>Mot de passe du compte de service
              <input v-model="form.secret" type="password" maxlength="4096" autocomplete="new-password" :placeholder="editing && provider.has_secret ? '•••••• (inchangé si vide)' : ''" />
            </label>
          </div>
        </fieldset>
        <fieldset>
          <legend>Recherche des utilisateurs</legend>
          <div class="form-grid">
            <label>Base de recherche<input v-model.trim="form.user_base" required maxlength="512" placeholder="DC=corp,DC=local" /></label>
            <label>Filtre ({username} une seule fois)<input v-model.trim="form.user_filter" required maxlength="512" /></label>
            <label>Attribut identifiant stable (vide = DN)<input v-model.trim="form.uid_attr" maxlength="64" /></label>
            <label>Attribut nom<input v-model.trim="form.display_attr" maxlength="64" /></label>
            <label>Attribut e-mail<input v-model.trim="form.mail_attr" maxlength="64" /></label>
            <label>Attribut groupes<input v-model.trim="form.group_attr" maxlength="64" /></label>
          </div>
          <details>
<summary>Bind direct et recherche de groupes (avancé)</summary>
            <div class="form-grid">
              <label>Modèle de DN pour bind direct (sans compte de service)<input v-model.trim="form.bind_dn_template" maxlength="512" placeholder="{username}@corp.local" /></label>
              <label>Base des groupes<input v-model.trim="form.group_base" maxlength="512" /></label>
              <label>Filtre des groupes ({user_dn})<input v-model.trim="form.group_filter" maxlength="512" /></label>
            </div>
          </details>
        </fieldset>
      </template>

      <fieldset>
        <legend>Rôles</legend>
        <p class="hint">
          Un compte externe ne peut jamais être super admin : seuls <strong>Opérateur</strong> (recherche, topologie, localisation en direct, export) et
          <strong>Lecteur</strong> (recherche, topologie) sont attribuables. Sans correspondance ni rôle par défaut, la connexion est refusée.
        </p>
        <div v-if="!noGroups" class="role-rows">
          <div v-for="(r, i) in form.rows" :key="i" class="role-row">
            <input v-model.trim="r.group" maxlength="512" :placeholder="isLdap ? 'Groupe (DN complet ou nom court)' : 'Valeur du groupe dans le jeton'" :aria-label="`Groupe ${i + 1}`" />
            <select v-model="r.role" :aria-label="`Rôle du groupe ${i + 1}`"><option value="operator">Opérateur</option><option value="viewer">Lecteur</option></select>
            <button type="button" class="ghost" :aria-label="`Retirer le groupe ${i + 1}`" @click="form.rows.splice(i, 1)">×</button>
          </div>
          <button type="button" class="ghost" @click="form.rows.push({ group: '', role: 'viewer' })">Ajouter un groupe</button>
        </div>
        <label>Rôle par défaut (si aucun groupe ne correspond)
          <select v-model="form.default_role"><option value="">Aucun : accès refusé</option><option value="viewer">Lecteur</option><option value="operator">Opérateur</option></select>
        </label>
      </fieldset>

      <div class="modal-foot">
        <button type="button" class="ghost" @click="emit('close')">Annuler</button>
        <button type="submit" :disabled="busy">{{ editing ? 'Enregistrer' : 'Créer' }}</button>
      </div>
    </form>
  </Modal>
</template>
