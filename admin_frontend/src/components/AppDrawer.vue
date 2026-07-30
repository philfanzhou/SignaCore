<script setup lang="ts">
import { useApps } from '../composables/useApps'
import { I } from '../utils/icons'

const {
  appDrawerVisible,
  appDrawerOpen,
  appDrawerApp,
  callbackForm,
  savingCallback,
  resettingSecret,
  closeAppDrawer,
  saveCallbackFromDrawer,
  handleResetSecret,
  openDeleteAppModal,
} = useApps()
</script>

<template>
  <!-- ============ 应用 Drawer ============ -->
  <template v-if="appDrawerVisible && appDrawerApp">
    <div class="overlay" :class="{ open: appDrawerOpen }" @click="closeAppDrawer"></div>
    <div class="drawer" :class="{ open: appDrawerOpen }">
      <div class="drawer-head">
        <div class="cell-app-icon" style="width: 40px; height: 40px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
        </div>
        <div style="flex: 1">
          <div class="drawer-title">{{ appDrawerApp.appName }}</div>
          <div class="drawer-sub mono">{{ appDrawerApp.appId }}</div>
        </div>
        <span class="badge" :class="appDrawerApp.isActive ? 'green' : 'gray'">
          <span class="dot"></span>{{ appDrawerApp.isActive ? '已启用' : '已停用' }}
        </span>
        <button class="icon-btn" @click="closeAppDrawer">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.x"></svg>
        </button>
      </div>
      <div class="drawer-body">
        <div class="card" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">回调配置</div>
          <div class="field">
            <label>回调地址（Callback URL）</label>
            <input v-model="callbackForm.callbackUrl" class="input" style="width: 100%" placeholder="https://your-app.example.com/auth/callback">
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
            <label style="margin: 0">启用该应用</label>
            <label class="switch">
              <input v-model="callbackForm.isActive" type="checkbox">
              <span class="track"></span>
            </label>
          </div>
        </div>
        <div class="danger-zone section-gap">
          <div class="dz-title">重置密钥</div>
          <div class="dz-desc">生成新的 App Secret，旧 Secret 立即失效。新 Secret 仅显示一次。</div>
          <button class="btn btn-danger btn-sm" :disabled="resettingSecret" @click="handleResetSecret(appDrawerApp)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.refresh"></svg>
            重置密钥
          </button>
          <div class="dz-title" style="margin-top: 14px">删除应用</div>
          <div class="dz-desc">删除后使用该应用接入的所有登录将立即失败。</div>
          <button class="btn btn-danger btn-sm" @click="openDeleteAppModal(appDrawerApp)">删除应用</button>
        </div>
      </div>
      <div class="drawer-foot">
        <button class="btn btn-ghost" @click="closeAppDrawer">取消</button>
        <button class="btn" :disabled="savingCallback" @click="saveCallbackFromDrawer">保存配置</button>
      </div>
    </div>
  </template>
</template>
