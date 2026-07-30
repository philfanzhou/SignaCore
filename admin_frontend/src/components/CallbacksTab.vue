<script setup lang="ts">
import { useApps } from '../composables/useApps'
import { I } from '../utils/icons'
import { formatDate } from '../utils/format'

const {
  apps,
  callbackForm,
  selectedApp,
  savingCallback,
  onAppSelected,
  handleSaveCallback,
} = useApps()
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <div class="page-title">回调管理</div>
        <div class="page-sub">配置 OAuth 回调地址和过期设置</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">回调配置</div>
          <div class="card-sub">选择应用后填写回调参数</div>
        </div>
      </div>

      <div class="field">
        <label>选择应用</label>
        <select v-model="callbackForm.appId" class="select" style="width: 100%" @change="onAppSelected">
          <option value="">请选择应用</option>
          <option v-for="app in apps" :key="app.appId" :value="app.appId">
            {{ app.appName }} ({{ app.appId }})
          </option>
        </select>
      </div>

      <div class="field">
        <label>回调地址（Callback URL）</label>
        <input v-model="callbackForm.callbackUrl" class="input" style="width: 100%" placeholder="留空则清除回调配置">
        <div class="hint">留空表示纯服务端应用，不使用浏览器回调。</div>
      </div>

      <div class="field">
        <label>回调有效期</label>
        <div class="input-with-unit">
          <input v-if="!callbackForm.neverExpire" v-model.number="callbackForm.ttlSeconds" class="input" type="number" min="1">
          <input v-else class="input" :value="'永不过期'" disabled>
          <select v-model="callbackForm.ttlUnit" class="select" :disabled="callbackForm.neverExpire">
            <option value="h">小时</option>
            <option value="d">天</option>
          </select>
        </div>
        <div class="hint">到期后回调地址自动失效，需重新配置。保存即从此刻重新计时。</div>
      </div>

      <div class="field" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0">
        <label style="margin: 0">永不过期</label>
        <label class="switch">
          <input v-model="callbackForm.neverExpire" type="checkbox">
          <span class="track"></span>
        </label>
      </div>

      <div class="field" style="display: flex; align-items: center; justify-content: space-between; margin-top: 16px; margin-bottom: 0">
        <label style="margin: 0">应用状态</label>
        <label class="switch">
          <input v-model="callbackForm.isActive" type="checkbox">
          <span class="track"></span>
        </label>
      </div>

      <div v-if="selectedApp" class="alert alert-info section-gap">
        <div class="alert-ico-box">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
        </div>
        <div>
          <strong>已选择：{{ selectedApp.appName }}</strong><br>
          当前回调：{{ selectedApp.callbackUrl || '未配置' }}，过期时间：{{ selectedApp.callbackExpiresAt ? formatDate(selectedApp.callbackExpiresAt) : '永不过期' }}
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; margin-top: 18px">
        <button class="btn" :disabled="savingCallback" @click="handleSaveCallback">
          <svg v-if="savingCallback" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          {{ savingCallback ? '保存中...' : '保存回调配置' }}
        </button>
      </div>
    </div>
  </div>
</template>
