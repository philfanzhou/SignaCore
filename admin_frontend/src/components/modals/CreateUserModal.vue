<script setup lang="ts">
import { useUsers } from '../../composables/useUsers'
import { I } from '../../utils/icons'

const {
  showCreateUserDialog,
  createUserForm,
  creatingUser,
  handleCreateUser,
} = useUsers()
</script>

<template>
  <!-- ============ 创建密码账户 Modal ============ -->
  <template v-if="showCreateUserDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showCreateUserDialog = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
          </div>
          <div>
            <div class="modal-title">创建密码账户</div>
            <div class="modal-sub" style="margin: 2px 0 0">标准账户，用户使用用户名与密码登录</div>
          </div>
        </div>
        <div class="field">
          <label>用户名</label>
          <input v-model="createUserForm.username" class="input" style="width: 100%" placeholder="如 zhang.wei" @keyup.enter="handleCreateUser">
        </div>
        <div class="field">
          <label>初始密码</label>
          <input v-model="createUserForm.password" class="input" type="password" style="width: 100%" placeholder="至少 8 位，建议首登后修改" @keyup.enter="handleCreateUser">
        </div>
        <div class="field">
          <label>备注</label>
          <input v-model="createUserForm.remark" class="input" style="width: 100%" placeholder="如 运营账号">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="showCreateUserDialog = false">取消</button>
          <button class="btn" :disabled="creatingUser" @click="handleCreateUser">
            <svg v-if="creatingUser" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingUser ? '创建中...' : '创建账户' }}
          </button>
        </div>
      </div>
    </div>
  </template>
</template>
