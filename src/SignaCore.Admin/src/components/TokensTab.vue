<script setup lang="ts">
import { useTokens } from '../composables/useTokens'
import { I } from '../utils/icons'

const { revokingToken, tokenForm, handleRevokeToken } = useTokens()
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <div class="page-title">令牌管理</div>
        <div class="page-sub">管理和吊销刷新令牌</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">吊销刷新令牌</div>
          <div class="card-sub">输入完整的 refresh token 字符串</div>
        </div>
      </div>

      <div class="alert alert-warning">
        <div class="alert-ico-box">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
        </div>
        <div>
          <strong>安全警告</strong><br>
          吊销刷新令牌将使其立即失效，用户需要重新认证。
        </div>
      </div>

      <div class="field">
        <label>刷新令牌</label>
        <textarea v-model="tokenForm.refreshToken" class="input" rows="4" placeholder="粘贴要吊销的刷新令牌"></textarea>
      </div>

      <div style="display: flex; justify-content: flex-end">
        <button class="btn btn-danger" :disabled="revokingToken" @click="handleRevokeToken">
          <svg v-if="revokingToken" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.logout"></svg>
          {{ revokingToken ? '吊销中...' : '吊销令牌' }}
        </button>
      </div>
    </div>
  </div>
</template>
