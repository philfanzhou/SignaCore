<script setup lang="ts">
import { useApps } from '../../composables/useApps'
import { I } from '../../utils/icons'

const {
  deleteAppOpen,
  deleteAppTarget,
  deleteAppConfirmId,
  deletingApp,
  handleDeleteApp,
} = useApps()
</script>

<template>
  <!-- ============ 删除应用二次确认 Modal ============ -->
  <template v-if="deleteAppOpen && deleteAppTarget">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="deleteAppOpen = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico danger">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
          </div>
          <div>
            <div class="modal-title">删除应用？</div>
            <div class="modal-sub" style="margin: 2px 0 0">删除后使用 <span class="mono">{{ deleteAppTarget.appId }}</span> 接入的登录将立即失败。请输入应用 ID 确认。</div>
          </div>
        </div>
        <div class="field">
          <input v-model="deleteAppConfirmId" class="input" style="width: 100%" :placeholder="deleteAppTarget.appId">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="deleteAppOpen = false">取消</button>
          <button class="btn btn-danger" :disabled="deleteAppConfirmId !== deleteAppTarget.appId || deletingApp" @click="handleDeleteApp(deleteAppTarget)">
            {{ deletingApp ? '删除中...' : '永久删除' }}
          </button>
        </div>
      </div>
    </div>
  </template>
</template>
