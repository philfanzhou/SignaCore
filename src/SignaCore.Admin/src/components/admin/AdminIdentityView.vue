<script setup lang="ts">
import { useAdminUsers } from "../../composables/admin/useAdminUsers";
import { formatDate, getInitials } from "../../utils/format";
import AdminUserDrawer from "./AdminUserDrawer.vue";
import AdminUserModal from "./AdminUserModal.vue";

const {
  userFilters,
  filteredUsers,
  userLoading,
  userError,
  userTotal,
  userPage,
  userPages,
  searchUsers,
  changeUserPage,
  toggleUser,
  openUser,
  userMode,
  userModalOpen,
  resetUserForm,
} = useAdminUsers();
</script>

<template>
  <section class="console-view">
    <div class="console-page-heading">
      <div>
        <h1>账户目录</h1>
        <p>管理平台账户状态，并在详情中核对登录历史。</p>
      </div>
      <div class="heading-actions">
        <button
          class="console-button secondary"
          @click="
            userMode = 'phone';
            resetUserForm();
            userModalOpen = true;
          "
        >
          ＋ 手机账户</button
        ><button
          class="console-button primary"
          @click="
            userMode = 'password';
            resetUserForm();
            userModalOpen = true;
          "
        >
          ＋ 密码账户
        </button>
      </div>
    </div>
    <article class="console-panel list-panel">
      <div class="filter-bar">
        <div class="console-search">
          <span>⌕</span
          ><input
            v-model="userFilters.username"
            placeholder="用户名"
            @keyup.enter="searchUsers"
          />
        </div>
        <div class="console-search">
          <span>⌕</span
          ><input
            v-model="userFilters.phone"
            placeholder="手机号"
            @keyup.enter="searchUsers"
          />
        </div>
        <select
          v-model="userFilters.status"
          class="console-select"
          aria-label="账户状态"
        >
          <option value="all">全部状态</option>
          <option value="active">已启用</option>
          <option value="disabled">已禁用</option></select
        ><button class="console-button secondary compact" @click="searchUsers">
          搜索
        </button>
      </div>
      <div class="list-summary">
        <span
          >当前页 {{ filteredUsers.length }} / 共 {{ userTotal }} 个账户</span
        ><span>状态筛选仅作用于当前服务端分页结果</span>
      </div>
      <div v-if="userLoading" class="console-table-state">
        <span class="console-spinner"></span>读取账户目录…
      </div>
      <div v-else-if="userError" class="console-table-state error">
        {{ userError }}
        <button class="text-button" @click="searchUsers">重试</button>
      </div>
      <div v-else-if="!filteredUsers.length" class="console-table-state">
        <span class="big-state-icon">◎</span><b>没有匹配账户</b
        ><small>调整筛选条件或创建一个新账户。</small>
      </div>
      <div v-else class="console-table-scroll">
        <table class="console-table">
          <thead>
            <tr>
              <th>账户</th>
              <th>账号类型</th>
              <th>联系方式</th>
              <th>创建时间</th>
              <th>状态</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="user in filteredUsers"
              :key="user.userId"
              tabindex="0"
              @click="openUser(user)"
              @keydown.enter="openUser(user)"
            >
              <td>
                <div class="table-primary">
                  <span class="console-avatar table-avatar">{{
                    getInitials(user.username || user.displayName || "?").slice(
                      0,
                      2,
                    )
                  }}</span
                  ><span
                    ><b>{{
                      user.displayName || user.username || user.userId
                    }}</b
                    ><small class="mono">{{
                      user.username || user.userId
                    }}</small></span
                  >
                </div>
              </td>
              <td>
                <span class="status-pill blue">{{
                  user.hasPassword ? "密码账户" : "手机账户"
                }}</span>
              </td>
              <td class="mono">{{ user.phone || "—" }}</td>
              <td>{{ formatDate(user.createdAt) }}</td>
              <td>
                <button
                  class="status-pill-button"
                  :class="user.isActive ? 'green' : 'gray'"
                  @click.stop="toggleUser(user)"
                >
                  <i></i>{{ user.isActive ? "已启用" : "已禁用" }}
                </button>
              </td>
              <td class="row-arrow">→</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="console-pager">
        <span>第 {{ userPage }} / {{ userPages }} 页</span
        ><button
          :disabled="userPage <= 1"
          @click="changeUserPage(userPage - 1)"
        >
          ←</button
        ><button
          :disabled="userPage >= userPages"
          @click="changeUserPage(userPage + 1)"
        >
          →
        </button>
      </div>
    </article>
  </section>
  <AdminUserDrawer /><AdminUserModal />
</template>
