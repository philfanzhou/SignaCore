<script setup lang="ts">
import { useUsers } from '../../composables/useUsers'
import { I } from '../../utils/icons'

const {
  showCreatePhoneUserDialog,
  createPhoneUserForm,
  creatingPhoneUser,
  handleCreatePhoneUser,
} = useUsers()
</script>

<template>
  <!-- ============ 创建手机账户 Modal ============ -->
  <template v-if="showCreatePhoneUserDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showCreatePhoneUserDialog = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
          </div>
          <div>
            <div class="modal-title">创建手机账户</div>
            <div class="modal-sub" style="margin: 2px 0 0">免密码账户，用户通过短信验证码登录</div>
          </div>
        </div>
        <div class="field">
          <label>手机号</label>
          <input v-model="createPhoneUserForm.phone" class="input" style="width: 100%" placeholder="11 位手机号" @keyup.enter="handleCreatePhoneUser">
        </div>
        <div class="field">
          <label>备注</label>
          <input v-model="createPhoneUserForm.remark" class="input" style="width: 100%" placeholder="如 备用联系人账号">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="showCreatePhoneUserDialog = false">取消</button>
          <button class="btn" :disabled="creatingPhoneUser" @click="handleCreatePhoneUser">
            <svg v-if="creatingPhoneUser" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingPhoneUser ? '创建中...' : '创建账户' }}
          </button>
        </div>
      </div>
    </div>
  </template>
</template>
