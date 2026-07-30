<script setup lang="ts">
import { useApps } from '../../composables/useApps'
import { I } from '../../utils/icons'

const {
  showSecretDialog,
  latestCreatedAppSecret,
  latestSecretAppId,
  secretCopied,
  secretSavedConfirmed,
  copySecret,
} = useApps()
</script>

<template>
  <!-- ============ 密钥显示 Modal ============ -->
  <template v-if="showSecretDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showSecretDialog = false; secretSavedConfirmed = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico warning">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.key"></svg>
          </div>
          <div>
            <div class="modal-title">保存你的 App Secret</div>
            <div class="modal-sub" style="margin: 2px 0 0">应用 <span class="mono">{{ latestSecretAppId }}</span> · 此密钥仅显示这一次，平台不做明文存储</div>
          </div>
        </div>
        <div class="secret-box">
          <code>{{ latestCreatedAppSecret }}</code>
          <button class="copy-btn" @click="copySecret(latestCreatedAppSecret)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="secretCopied ? I.check : I.copy"></svg>
            <span>{{ secretCopied ? '已复制' : '复制' }}</span>
          </button>
        </div>
        <label class="check-line">
          <input v-model="secretSavedConfirmed" type="checkbox">
          <span>我已将密钥保存到安全位置</span>
        </label>
        <div class="modal-actions">
          <button class="btn" :disabled="!secretSavedConfirmed" @click="showSecretDialog = false; secretSavedConfirmed = false">完成</button>
        </div>
      </div>
    </div>
  </template>
</template>
