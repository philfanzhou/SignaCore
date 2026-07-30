<script setup lang="ts">
import { useUsers } from '../composables/useUsers'
import { I } from '../utils/icons'
import { formatDate, getInitials } from '../utils/format'

const {
  userFilters,
  userStatusFilter,
  users,
  filteredUsers,
  activeUsersInPage,
  disabledUsersInPage,
  loadingUsers,
  userTotal,
  page,
  totalPages,
  pageNumbers,
  handleSearch,
  handlePageChange,
  handleToggleUserStatus,
  openCreateUserDialog,
  openCreatePhoneUserDialog,
  openUserDrawer,
} = useUsers()
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <div class="page-title">用户管理</div>
        <div class="page-sub">平台账户的开户、检索与处置</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-ghost" @click="openCreatePhoneUserDialog">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.plus"></svg>
          手机账户
        </button>
        <button class="btn" @click="openCreateUserDialog">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.plus"></svg>
          密码账户
        </button>
      </div>
    </div>

    <div class="card">
      <div style="display: flex; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; align-items: center">
        <div class="input-wrap" style="flex: 1; min-width: 220px; max-width: 340px">
          <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.search"></svg>
          <input v-model="userFilters.username" class="input" placeholder="搜索用户名" @keyup.enter="handleSearch">
        </div>
        <div class="input-wrap" style="flex: 1; min-width: 220px; max-width: 340px">
          <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.search"></svg>
          <input v-model="userFilters.phone" class="input" placeholder="搜索手机号" @keyup.enter="handleSearch">
        </div>
        <button class="btn btn-ghost btn-sm" @click="handleSearch" title="搜索">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.search"></svg>
          搜索
        </button>
        <div class="chips">
          <button class="chip" :class="{ active: userStatusFilter === 'all' }" @click="userStatusFilter = 'all'">全部 {{ users.length }}</button>
          <button class="chip" :class="{ active: userStatusFilter === 'active' }" @click="userStatusFilter = 'active'">已启用 {{ activeUsersInPage }}</button>
          <button class="chip" :class="{ active: userStatusFilter === 'disabled' }" @click="userStatusFilter = 'disabled'">已禁用 {{ disabledUsersInPage }}</button>
        </div>
      </div>

      <div v-if="loadingUsers" class="loading-state">
        <svg class="spinner" viewBox="0 0 50 50">
          <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
            <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
          </circle>
        </svg>
        <div>加载中...</div>
      </div>
      <div v-else-if="filteredUsers.length === 0" class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
        <br>没有匹配的账户，试试调整筛选条件
      </div>
      <div v-else class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>用户</th>
              <th>手机号</th>
              <th>类型</th>
              <th>备注</th>
              <th>创建时间</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="user in filteredUsers"
              :key="user.userId"
              class="clickable"
              @click="openUserDrawer(user)"
            >
              <td>
                <div class="cell-flex">
                  <div class="cell-avatar" :class="{ disabled: !user.isActive }">{{ getInitials(user.username || user.displayName || '?').slice(0, 1) }}</div>
                  <div>
                    <div class="td-main">{{ user.username || user.displayName || user.userId }}</div>
                    <div class="td-sub mono">{{ user.userId }}</div>
                  </div>
                </div>
              </td>
              <td class="mono" style="font-size: 12.5px">{{ user.phone || '-' }}</td>
              <td>
                <span class="badge" :class="user.hasPassword ? 'indigo' : 'blue'">
                  {{ user.hasPassword ? '密码账户' : '手机账户' }}
                </span>
              </td>
              <td style="color: var(--text-2); max-width: 200px">{{ user.remark || '-' }}</td>
              <td style="color: var(--text-3); font-size: 12.5px; font-variant-numeric: tabular-nums">{{ formatDate(user.createdAt) }}</td>
              <td @click.stop>
                <label class="switch" :title="user.isActive ? '点击禁用' : '点击启用'">
                  <input type="checkbox" :checked="user.isActive" @change="handleToggleUserStatus(user, $event)">
                  <span class="track"></span>
                </label>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="pager">
        <span class="total">共 {{ userTotal }} 个账户</span>
        <button :disabled="page <= 1" @click="handlePageChange(page - 1)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(180deg)">
            <path d="M9 6l6 6-6 6"/>
          </svg>
        </button>
        <button v-for="p in pageNumbers" :key="p" :class="{ cur: page === p }" @click="handlePageChange(p)">{{ p }}</button>
        <button :disabled="page >= totalPages" @click="handlePageChange(page + 1)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 6l6 6-6 6"/>
          </svg>
        </button>
      </div>
    </div>
  </div>
</template>
