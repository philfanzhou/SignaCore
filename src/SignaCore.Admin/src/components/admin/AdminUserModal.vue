<script setup lang="ts">
import { useAdminUsers } from "../../composables/admin/useAdminUsers";

const { userMode, userModalOpen, userSaving, createUserForm, saveUser } =
  useAdminUsers();
</script>

<template>
  <div
    v-if="userModalOpen"
    class="console-modal-layer"
    @click.self="userModalOpen = false"
  >
    <section
      class="console-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="user-modal-title"
    >
      <div class="modal-header">
        <div>
          <span class="console-eyebrow">NEW ACCOUNT</span>
          <h2 id="user-modal-title">
            创建{{ userMode === "password" ? "密码" : "手机" }}账户
          </h2>
        </div>
        <button
          class="close-button"
          aria-label="关闭"
          @click="userModalOpen = false"
        >
          ×
        </button>
      </div>
      <div class="modal-body">
        <div class="mode-switch">
          <button
            :class="{ active: userMode === 'password' }"
            @click="userMode = 'password'"
          >
            密码账户</button
          ><button
            :class="{ active: userMode === 'phone' }"
            @click="userMode = 'phone'"
          >
            手机账户
          </button>
        </div>
        <label v-if="userMode === 'password'"
          >用户名<input
            v-model="createUserForm.username"
            class="console-input"
            autocomplete="off" /></label
        ><label v-else
          >手机号<input
            v-model="createUserForm.phone"
            class="console-input"
            inputmode="tel"
            placeholder="13800000000" /></label
        ><label v-if="userMode === 'password'"
          >初始密码<input
            v-model="createUserForm.password"
            class="console-input"
            type="password"
            autocomplete="new-password"
          /><small>至少 8 位，且包含大写、小写和数字。</small></label
        ><label
          >显示名称<input
            v-model="createUserForm.displayName"
            class="console-input" /></label
        ><label
          >昵称<input
            v-model="createUserForm.nickname"
            class="console-input" /></label
        ><label
          >备注<textarea
            v-model="createUserForm.remark"
            class="console-input"
            rows="3"
          ></textarea>
        </label>
      </div>
      <div class="modal-footer">
        <button class="console-button secondary" @click="userModalOpen = false">
          取消</button
        ><button
          class="console-button primary"
          :disabled="userSaving"
          @click="saveUser"
        >
          {{ userSaving ? "创建中…" : "创建账户" }}
        </button>
      </div>
    </section>
  </div>
</template>
