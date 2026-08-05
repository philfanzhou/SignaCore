<script setup lang="ts">
import { useApps } from '../../composables/useApps'
import { I } from '../../utils/icons'

const {
  showCreateAppDialog,
  createAppForm,
  creatingApp,
  handleCreateApp,
} = useApps()
</script>

<template>
  <!-- ============ 注册应用 Modal ============ -->
  <template v-if="showCreateAppDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showCreateAppDialog = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
          </div>
          <div>
            <div class="modal-title">注册应用</div>
            <div class="modal-sub" style="margin: 2px 0 0">为新的业务系统创建 OAuth 接入凭证</div>
          </div>
        </div>
        <div class="field">
          <label>应用名称</label>
          <input v-model="createAppForm.appName" class="input" style="width: 100%" placeholder="如 业务门户" @keyup.enter="handleCreateApp">
        </div>
        <div class="field">
          <label>回调地址（可选）</label>
          <input v-model="createAppForm.callbackUrl" class="input" style="width: 100%" placeholder="https://your-app.example.com/auth/callback">
        </div>
        <div class="field">
          <label>回调有效期</label>
          <div class="input-with-unit">
            <input v-if="!createAppForm.neverExpire" v-model.number="createAppForm.ttlSeconds" class="input" type="number" min="1">
            <input v-else class="input" :value="'永不过期'" disabled>
            <select v-model="createAppForm.ttlUnit" class="select" :disabled="createAppForm.neverExpire">
              <option value="h">小时</option>
              <option value="d">天</option>
            </select>
          </div>
        </div>
        <label class="check-line" style="margin-top: 4px">
          <input v-model="createAppForm.neverExpire" type="checkbox">
          <span>永不过期</span>
        </label>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="showCreateAppDialog = false">取消</button>
          <button class="btn" :disabled="creatingApp" @click="handleCreateApp">
            <svg v-if="creatingApp" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingApp ? '创建中...' : '创建并生成密钥' }}
          </button>
        </div>
      </div>
    </div>
  </template>
</template>
