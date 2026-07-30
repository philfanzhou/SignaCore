<script setup lang="ts">
import { useUsers } from '../composables/useUsers'
import { I } from '../utils/icons'
import { formatDate, getInitials } from '../utils/format'

const {
  userDrawerVisible,
  userDrawerOpen,
  userDrawerUser,
  userDrawerTab,
  closeUserDrawer,
  toggleDrawerUserStatus,
  openEditRemarkModal,
} = useUsers()
</script>

<template>
  <!-- ============ 用户 Drawer ============ -->
  <template v-if="userDrawerVisible && userDrawerUser">
    <div class="overlay" :class="{ open: userDrawerOpen }" @click="closeUserDrawer"></div>
    <div class="drawer" :class="{ open: userDrawerOpen }">
      <div class="drawer-head">
        <div class="avatar" style="width: 40px; height: 40px; font-size: 14px">{{ getInitials(userDrawerUser.username || userDrawerUser.displayName || '?').slice(0, 1) }}</div>
        <div style="flex: 1">
          <div class="drawer-title">{{ userDrawerUser.username || userDrawerUser.displayName || userDrawerUser.userId }}</div>
          <div class="drawer-sub mono">{{ userDrawerUser.userId }}{{ userDrawerUser.username ? ' · ' + userDrawerUser.username : '' }}</div>
        </div>
        <span class="badge" :class="userDrawerUser.isActive ? 'green' : 'gray'">
          <span class="dot"></span>{{ userDrawerUser.isActive ? '已启用' : '已禁用' }}
        </span>
        <button class="icon-btn" @click="closeUserDrawer">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.x"></svg>
        </button>
      </div>
      <div class="drawer-body">
        <div class="mini-tabs">
          <button class="mini-tab" :class="{ active: userDrawerTab === 'info' }" @click="userDrawerTab = 'info'">基本信息</button>
        </div>
        <div class="card" style="padding: 18px">
          <dl class="kv">
            <dt>手机号</dt>
            <dd class="mono">{{ userDrawerUser.phone || '-' }}</dd>
            <dt>账户类型</dt>
            <dd>{{ userDrawerUser.hasPassword ? '密码账户' : '手机账户（短信验证码登录）' }}</dd>
            <dt>备注</dt>
            <dd>
              {{ userDrawerUser.remark || '-' }}
              <button class="btn btn-ghost btn-sm" style="margin-left: 6px" @click="openEditRemarkModal(userDrawerUser)">编辑</button>
            </dd>
            <dt>创建时间</dt>
            <dd style="font-variant-numeric: tabular-nums">{{ formatDate(userDrawerUser.createdAt) }}</dd>
          </dl>
        </div>
      </div>
      <div class="drawer-foot">
        <button class="btn btn-ghost" @click="closeUserDrawer">关闭</button>
        <button
          :class="userDrawerUser.isActive ? 'btn btn-danger' : 'btn'"
          @click="toggleDrawerUserStatus"
        >
          {{ userDrawerUser.isActive ? '禁用账户' : '启用账户' }}
        </button>
      </div>
    </div>
  </template>
</template>
