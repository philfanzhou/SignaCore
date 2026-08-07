<script setup lang="ts">
import { useApps } from '../composables/useApps'
import { I } from '../utils/icons'
import { formatTtl } from '../utils/format'

const {
  loadingApps,
  apps,
  openCreateAppDialog,
  openAppDrawer,
} = useApps()
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <div class="page-title">应用注册</div>
        <div class="page-sub">接入平台的业务系统及其 OAuth 配置</div>
      </div>
      <div class="page-actions">
        <button class="btn" @click="openCreateAppDialog">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.plus"></svg>
          注册应用
        </button>
      </div>
    </div>

    <div class="card">
      <div v-if="loadingApps" class="loading-state">
        <svg class="spinner" viewBox="0 0 50 50">
          <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
            <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
          </circle>
        </svg>
        <div>加载中...</div>
      </div>
      <div v-else-if="apps.length === 0" class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
        <br>没有注册应用
      </div>
      <div v-else class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>应用</th>
              <th>App ID</th>
              <th>回调地址</th>
              <th>回调有效期</th>
              <th>LDAP</th>
              <th>短信</th>
              <th>微信</th>
              <th>状态</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="app in apps"
              :key="app.appId"
              class="clickable"
              @click="openAppDrawer(app)"
            >
              <td>
                <div class="cell-flex">
                  <div class="cell-app-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
                  </div>
                  <span class="td-main">{{ app.appName }}</span>
                </div>
              </td>
              <td class="mono" style="color: var(--text-2)">{{ app.appId }}</td>
              <td style="max-width: 240px">
                <span class="mono" style="font-size: 12px" :style="{ color: app.callbackUrl ? 'var(--text-2)' : 'var(--text-3)' }">{{ app.callbackUrl || '未配置' }}</span>
              </td>
              <td style="font-variant-numeric: tabular-nums">{{ formatTtl(app) }}</td>
              <td>
                <span class="badge" :class="app.ldapLoginMode === 'Disabled' ? 'gray' : 'green'">
                  <span class="dot"></span>{{ app.ldapLoginMode === 'Disabled' ? '禁用' : app.ldapLoginMode === 'ManualApproval' ? '人工准入' : '自动开户' }}
                </span>
              </td>
              <td>
                <span class="badge" :class="app.smsLoginMode === 'Disabled' ? 'gray' : 'green'">
                  <span class="dot"></span>{{ app.smsLoginMode === 'Disabled' ? '禁用' : app.smsLoginMode === 'ManualApproval' ? '人工准入' : '自动开户' }}
                </span>
              </td>
              <td>
                <span class="badge" :class="app.wechatLoginMode === 'Disabled' ? 'gray' : 'green'">
                  <span class="dot"></span>{{ app.wechatLoginMode === 'Disabled' ? '禁用' : app.wechatLoginMode === 'BindRequired' ? '需绑定' : '自动开户' }}
                </span>
              </td>
              <td>
                <span class="badge" :class="app.isActive ? 'green' : 'gray'">
                  <span class="dot"></span>{{ app.isActive ? '已启用' : '已停用' }}
                </span>
              </td>
              <td style="color: var(--text-3); width: 30px">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.chev"></svg>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card section-gap" style="display: flex; gap: 14px; align-items: center; background: var(--info-soft); border-color: var(--info-line)">
      <div class="alert-ico-box" style="background: #fff; color: var(--info)">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.key"></svg>
      </div>
      <div style="font-size: 12.5px; color: #075985">App Secret 仅在创建或重置时显示一次，平台不做明文存储。需要轮换密钥时请进入应用详情操作，旧 Secret 将立即失效。</div>
    </div>
  </div>
</template>
