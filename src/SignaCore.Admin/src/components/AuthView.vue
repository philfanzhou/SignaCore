<script setup lang="ts">
import { appTitle, checkingSession, isAuthenticated, loggingIn, loginForm, handleLogin } from '../composables/useSession'
import { I } from '../utils/icons'
</script>

<template>
  <!-- 会话检查中 -->
  <div v-if="checkingSession" class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="auth-logo">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.idCard"></svg>
        </div>
        <div>
          欢迎回来
          <div class="auth-card-header-sub">{{ appTitle }} 管理控制台</div>
        </div>
      </div>
      <div class="auth-card-body">
        <div class="auth-loading">
          <svg class="spinner auth-spinner" viewBox="0 0 50 50">
            <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
              <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>正在验证登录状态...</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 未登录 -->
  <div v-else-if="!isAuthenticated" class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="auth-logo">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.idCard"></svg>
        </div>
        <div>
          欢迎回来
          <div class="auth-card-header-sub">{{ appTitle }} 管理控制台</div>
        </div>
      </div>
      <div class="auth-card-body">
        <div class="auth-subtitle">请登录管理员账号</div>

        <div class="field">
          <label>用户名</label>
          <div class="input-wrap">
            <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="9" cy="8" r="3.2"/><path d="M3.5 19.5c.6-3.2 2.8-4.8 5.5-4.8s4.9 1.6 5.5 4.8"/><circle cx="17" cy="9" r="2.4"/><path d="M15.6 14.9c2.6.1 4.3 1.5 4.9 4.1"/>
            </svg>
            <input v-model="loginForm.username" class="input" type="text" placeholder="请输入管理员用户名" :disabled="loggingIn" @keyup.enter="handleLogin">
          </div>
        </div>

        <div class="field">
          <label>密码</label>
          <div class="input-wrap">
            <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="8" cy="15.5" r="4"/><path d="M11 12.5L20 3.5M16.5 7l3 3M13.8 9.7l2.5 2.5"/>
            </svg>
            <input v-model="loginForm.password" class="input" type="password" placeholder="请输入密码" :disabled="loggingIn" @keyup.enter="handleLogin">
          </div>
        </div>

        <label class="check-line">
          <input v-model="loginForm.rememberMe" type="checkbox" :disabled="loggingIn">
          <span>7天内免登录</span>
        </label>

        <button class="btn btn-block" style="margin-top: 16px" :disabled="loggingIn" @click="handleLogin">
          <svg v-if="loggingIn" class="spinner" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          {{ loggingIn ? '登录中...' : '登录' }}
        </button>
      </div>
    </div>
  </div>
</template>
