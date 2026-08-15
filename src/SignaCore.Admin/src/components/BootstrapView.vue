<script setup lang="ts">
import { computed } from 'vue'
import {
  applyProviderDefaults,
  bootstrapAdvanced,
  bootstrapError,
  bootstrapFilePath,
  bootstrapForm,
  bootstrapMessage,
  bootstrapPhase,
  bootstrapProviders,
  saveBootstrap,
  testBootstrap,
} from '../composables/useBootstrap'

const selectedProvider = computed(() =>
  bootstrapProviders.value.find(item => item.provider === bootstrapForm.provider),
)
const isSqlite = computed(() => bootstrapForm.provider === 'SQLite')
const busy = computed(() => bootstrapPhase.value === 'testing' || bootstrapPhase.value === 'saving')

function providerChanged() {
  const provider = selectedProvider.value
  if (provider) applyProviderDefaults(provider)
}
</script>

<template>
  <div class="auth-page">
    <div class="auth-card" style="max-width: 680px; width: calc(100% - 32px)">
      <div class="auth-card-header">
        <div>
          Bootstrap configuration
          <div class="auth-card-header-sub">Connect SignaCore to its business database</div>
        </div>
      </div>

      <div v-if="bootstrapPhase === 'restarting'" class="auth-card-body">
        <div class="auth-loading">Configuration saved. Waiting for the service to restart…</div>
        <div v-if="bootstrapMessage" class="auth-subtitle" style="margin-top: 12px">
          {{ bootstrapMessage }}
        </div>
      </div>

      <div v-else class="auth-card-body">
        <div class="auth-subtitle">
          This protected workflow writes <code>{{ bootstrapFilePath }}</code>. The database password
          and master key are write-only and are never returned by the service.
        </div>

        <div class="field">
          <label>Database provider</label>
          <select v-model="bootstrapForm.provider" class="select" style="width: 100%" :disabled="busy" @change="providerChanged">
            <option v-for="provider in bootstrapProviders" :key="provider.provider" :value="provider.provider">
              {{ provider.provider }}{{ provider.singleInstanceOnly ? ' (single instance only)' : '' }}
            </option>
          </select>
        </div>

        <div v-if="!isSqlite" class="field">
          <label>Server version</label>
          <select v-if="selectedProvider?.serverVersions.length" v-model="bootstrapForm.serverVersion" class="select" style="width: 100%" :disabled="busy">
            <option v-for="version in selectedProvider.serverVersions" :key="version" :value="version">{{ version }}</option>
          </select>
          <input v-else v-model="bootstrapForm.serverVersion" class="input" :disabled="busy">
        </div>

        <div class="field">
          <label style="display: flex; gap: 8px; align-items: center">
            <input v-model="bootstrapAdvanced" type="checkbox" :disabled="busy">
            Use an advanced full connection string
          </label>
        </div>

        <div v-if="bootstrapAdvanced" class="field">
          <label>Connection string (write-only)</label>
          <input v-model="bootstrapForm.connectionString" class="input" type="password" autocomplete="off" :disabled="busy">
        </div>

        <template v-else-if="isSqlite">
          <div class="field">
            <label>SQLite file</label>
            <input v-model="bootstrapForm.filePath" class="input" :disabled="busy">
          </div>
          <div class="auth-subtitle">SQLite is supported only for a single active instance.</div>
        </template>

        <template v-else>
          <div class="field"><label>Host</label><input v-model="bootstrapForm.host" class="input" :disabled="busy"></div>
          <div class="field"><label>Port</label><input v-model.number="bootstrapForm.port" class="input" type="number" :disabled="busy"></div>
          <div class="field"><label>Database</label><input v-model="bootstrapForm.database" class="input" :disabled="busy"></div>
          <div class="field"><label>Username</label><input v-model="bootstrapForm.username" class="input" autocomplete="off" :disabled="busy"></div>
          <div class="field"><label>Password (write-only)</label><input v-model="bootstrapForm.password" class="input" type="password" autocomplete="new-password" :disabled="busy"></div>
        </template>

        <div class="field">
          <label>Installation type</label>
          <select v-model="bootstrapForm.installMode" class="select" style="width: 100%" :disabled="busy">
            <option value="new">New installation — generate a master key</option>
            <option value="existing">Existing installation / recovery</option>
          </select>
        </div>

        <div v-if="bootstrapForm.installMode === 'existing'" class="field">
          <label>Existing master key (write-only)</label>
          <input v-model="bootstrapForm.masterKey" class="input" type="password" autocomplete="off" :disabled="busy">
        </div>

        <div class="field">
          <label>One-time bootstrap code</label>
          <input v-model="bootstrapForm.bootstrapCode" class="input" autocomplete="off" :disabled="busy" @keyup.enter="saveBootstrap">
          <div class="auth-subtitle" style="margin-top: 6px">Read this code once from the process standard output or container log.</div>
        </div>

        <div v-if="bootstrapMessage" class="alert alert-info" style="margin-top: 12px">{{ bootstrapMessage }}</div>
        <div v-if="bootstrapError" class="auth-subtitle" style="margin-top: 12px; color: var(--danger)">{{ bootstrapError }}</div>

        <div style="display: flex; gap: 8px; margin-top: 16px">
          <button class="btn btn-ghost" :disabled="busy" @click="testBootstrap">
            {{ bootstrapPhase === 'testing' ? 'Testing…' : 'Test database' }}
          </button>
          <button class="btn" :disabled="busy" @click="saveBootstrap">
            {{ bootstrapPhase === 'saving' ? 'Saving…' : 'Save and restart' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
