<script setup lang="ts">
import { onMounted } from 'vue'
import { setupForm, setupPhase, setupError, submitSetup, prefillPublicBaseUrl } from '../composables/useSetup'
import { I } from '../utils/icons'

const appTitle = window.__APP_TITLE__ || 'SignaCore'

onMounted(prefillPublicBaseUrl)
</script>

<template>
  <div class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="auth-logo">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.idCard"></svg>
        </div>
        <div>
          初始化
          <div class="auth-card-header-sub">{{ appTitle }} 首次配置</div>
        </div>
      </div>

      <!-- 配置已保存，等待服务重启 -->
      <div v-if="setupPhase === 'restarting' || setupPhase === 'completed'" class="auth-card-body">
        <div class="auth-loading">
          <svg class="spinner auth-spinner" viewBox="0 0 50 50">
            <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
              <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>配置已保存，服务正在启动...</div>
        </div>
        <div v-if="setupError" class="auth-subtitle" style="margin-top: 16px">{{ setupError }}</div>
      </div>

      <!-- 首次配置表单 -->
      <div v-else class="auth-card-body">
        <div class="auth-subtitle">
          该数据库尚未初始化。请填写下列信息完成首次配置。
        </div>

        <div class="field">
          <label>对外访问地址</label>
          <div class="input-wrap">
            <input
              v-model="setupForm.publicBaseUrl"
              class="input"
              type="url"
              placeholder="https://id.example.com"
              :disabled="setupPhase === 'saving'"
            >
          </div>
          <div class="auth-subtitle" style="margin-top: 6px">
            下游服务据此获取发现文档与 JWKS，同时作为 JWT 的 issuer。默认必须使用 HTTPS。
          </div>
        </div>

        <div class="field">
          <label style="display: flex; gap: 8px; align-items: center">
            <input
              v-model="setupForm.allowNonHttpsIssuer"
              type="checkbox"
              :disabled="setupPhase === 'saving'"
            >
            明确允许使用不安全的 HTTP issuer
          </label>
          <div class="auth-subtitle" style="margin-top: 6px">
            默认关闭。系统不会根据 IP、主机名或 Docker 网络自动判断例外。
          </div>
        </div>

        <div class="field">
          <label>JWT audience</label>
          <div class="input-wrap">
            <input
              v-model="setupForm.jwtAudience"
              class="input"
              type="text"
              placeholder="SignaCore.Services"
              :disabled="setupPhase === 'saving'"
            >
          </div>
        </div>

        <div class="field">
          <label>管理员用户名</label>
          <div class="input-wrap">
            <input
              v-model="setupForm.username"
              class="input"
              type="text"
              placeholder="请输入管理员用户名"
              :disabled="setupPhase === 'saving'"
            >
          </div>
        </div>

        <div class="field">
          <label>管理员密码</label>
          <div class="input-wrap">
            <input
              v-model="setupForm.password"
              class="input"
              type="password"
              placeholder="请输入密码"
              :disabled="setupPhase === 'saving'"
            >
          </div>
        </div>

        <div class="field">
          <label>确认密码</label>
          <div class="input-wrap">
            <input
              v-model="setupForm.confirmPassword"
              class="input"
              type="password"
              placeholder="请再次输入密码"
              :disabled="setupPhase === 'saving'"
            >
          </div>
        </div>

        <div class="field">
          <label>一次性初始化码</label>
          <div class="input-wrap">
            <input
              v-model="setupForm.setupCode"
              class="input"
              type="text"
              placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
              :disabled="setupPhase === 'saving'"
              @keyup.enter="submitSetup"
            >
          </div>
          <div class="auth-subtitle" style="margin-top: 6px">
            初始化码在服务首次启动时打印到标准输出（容器日志）。丢失后可执行
            <code>dotnet SignaCore.Host.dll --rotate-setup-code</code> 重新生成。
          </div>
        </div>

        <div v-if="setupError" class="auth-subtitle" style="margin-top: 12px; color: var(--danger)">
          {{ setupError }}
        </div>

        <button
          class="btn btn-block"
          style="margin-top: 16px"
          :disabled="setupPhase === 'saving'"
          @click="submitSetup"
        >
          <svg v-if="setupPhase === 'saving'" class="spinner" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          {{ setupPhase === 'saving' ? '正在初始化...' : '完成初始化' }}
        </button>
      </div>
    </div>
  </div>
</template>
