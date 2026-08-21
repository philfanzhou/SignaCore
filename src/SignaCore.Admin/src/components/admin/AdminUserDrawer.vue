<script setup lang="ts">
import { useAdminUsers } from "../../composables/admin/useAdminUsers";
import { formatDate, getInitials } from "../../utils/format";

const {
  selectedUser,
  userDrawerOpen,
  userDrawerTab,
  userHistory,
  userHistoryTotal,
  userHistoryLoading,
  userMeta,
  updateUserMeta,
  toggleUser,
  closeUserDrawer,
  loadUserHistory,
} = useAdminUsers();
</script>

<template>
  <div
    v-if="userDrawerOpen && selectedUser"
    class="console-overlay-layer"
    @click.self="closeUserDrawer"
  >
    <aside
      class="console-drawer user-drawer"
      role="dialog"
      aria-modal="true"
      aria-label="账户详情"
    >
      <div class="drawer-header">
        <div>
          <span class="console-eyebrow">ACCOUNT DETAIL</span>
          <h2>
            {{
              selectedUser.displayName ||
              selectedUser.username ||
              selectedUser.userId
            }}
          </h2>
          <p class="mono">{{ selectedUser.userId }}</p>
        </div>
        <button
          class="close-button"
          aria-label="关闭账户详情"
          @click="closeUserDrawer"
        >
          ×
        </button>
      </div>
      <div class="drawer-tabs">
        <button
          :class="{ active: userDrawerTab === 'profile' }"
          @click="userDrawerTab = 'profile'"
        >
          账户资料</button
        ><button
          :class="{ active: userDrawerTab === 'history' }"
          @click="
            userDrawerTab = 'history';
            loadUserHistory();
          "
        >
          登录历史 <span>{{ userHistoryTotal }}</span>
        </button>
      </div>
      <div class="drawer-body">
        <template v-if="userDrawerTab === 'profile'"
          ><div class="detail-identity">
            <span class="console-avatar large">{{
              getInitials(
                selectedUser.username || selectedUser.displayName || "?",
              ).slice(0, 2)
            }}</span>
            <div>
              <b>{{ selectedUser.username || "手机账户" }}</b>
              <p>
                {{
                  selectedUser.phone ||
                  (selectedUser.hasPassword ? "密码已设置" : "未绑定手机号")
                }}
              </p>
            </div>
            <span
              class="status-pill"
              :class="selectedUser.isActive ? 'green' : 'gray'"
              ><i></i>{{ selectedUser.isActive ? "已启用" : "已禁用" }}</span
            >
          </div>
          <div class="detail-grid">
            <div>
              <span>账号类型</span
              ><b>{{ selectedUser.hasPassword ? "密码账户" : "手机账户" }}</b>
            </div>
            <div>
              <span>创建时间</span
              ><b>{{ formatDate(selectedUser.createdAt) }}</b>
            </div>
          </div>
          <label class="drawer-field"
            >昵称<input
              v-model="userMeta.nickname"
              class="console-input"
            /><button class="inline-save" @click="updateUserMeta('nickname')">
              保存
            </button></label
          ><label class="drawer-field"
            >备注<textarea
              v-model="userMeta.remark"
              class="console-input"
              rows="3"
            ></textarea
            ><button class="inline-save" @click="updateUserMeta('remark')">
              保存
            </button></label
          >
          <div class="drawer-divider"></div>
          <button
            class="console-button"
            :class="selectedUser.isActive ? 'danger' : 'secondary'"
            @click="toggleUser(selectedUser)"
          >
            {{ selectedUser.isActive ? "禁用账户" : "启用账户" }}
          </button></template
        ><template v-else
          ><div v-if="userHistoryLoading" class="console-table-state">
            <span class="console-spinner"></span>读取登录历史…
          </div>
          <div v-else-if="!userHistory.length" class="console-table-state">
            <span class="big-state-icon">⌁</span><b>暂无登录历史</b>
          </div>
          <div v-else class="history-list">
            <div
              v-for="item in userHistory"
              :key="`${item.createdAt}-${item.clientIp}-${item.eventType}`"
              class="history-row"
            >
              <span
                class="status-dot"
                :class="item.eventType.includes('failure') ? 'red' : 'green'"
              ></span>
              <div>
                <b>{{ item.eventType }} · {{ item.authMethod }}</b>
                <p>
                  {{ item.clientIp || "未知 IP" }} ·
                  {{ formatDate(item.createdAt) }}
                </p>
                <small v-if="item.failureReason" class="danger-text">{{
                  item.failureReason
                }}</small>
              </div>
            </div>
          </div></template
        >
      </div>
    </aside>
  </div>
</template>
