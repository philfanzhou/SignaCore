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
  userSessions,
  userSessionsTotal,
  userSessionsLoading,
  userSessionRevokingId,
  userMeta,
  updateUserMeta,
  toggleUser,
  closeUserDrawer,
  loadUserHistory,
  loadUserSessions,
  revokeUserSession,
} = useAdminUsers();

const sessionStatusText: Record<string, string> = {
  active: "活动",
  idleexpired: "空闲过期",
  absoluteexpired: "绝对过期",
  revoked: "已撤销",
};

function sessionStatusClass(status: string) {
  if (status === "active") return "green";
  if (status === "revoked") return "red";
  return "gray";
}
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
          登录历史 <span>{{ userHistoryTotal }}</span></button
        ><button
          :class="{ active: userDrawerTab === 'sessions' }"
          @click="
            userDrawerTab = 'sessions';
            loadUserSessions();
          "
        >
          身份会话 <span>{{ userSessionsTotal }}</span>
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
        ><template v-else-if="userDrawerTab === 'history'"
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
        ><template v-else
          >
          <div v-if="userSessionsLoading" class="console-table-state">
            <span class="console-spinner"></span>读取身份会话…
          </div>
          <div v-else-if="!userSessions.length" class="console-table-state">
            <span class="big-state-icon">⏱</span><b>暂无身份会话</b>
          </div>
          <div v-else class="history-list">
            <div
              v-for="session in userSessions"
              :key="session.id"
              class="history-row"
            >
              <span
                class="status-dot"
                :class="sessionStatusClass(session.status)"
              ></span>
              <div>
                <b>
                  {{ sessionStatusText[session.status] || session.status }} ·
                  {{ session.authMethod }}
                </b>
                <p>登录 {{ formatDate(session.authTime) }}</p>
                <p>
                  最近活跃 {{ formatDate(session.lastSeenAt) }} · 空闲截止
                  {{ formatDate(session.idleExpiresAt) }}
                </p>
                <small v-if="session.revokedAt" class="danger-text">
                  已于 {{ formatDate(session.revokedAt) }} 撤销（原因：{{
                    session.revocationReason || "未知"
                  }}）
                </small>
              </div>
              <button
                v-if="session.status === 'active'"
                class="console-button danger compact"
                :disabled="userSessionRevokingId === session.id"
                @click="revokeUserSession(session)"
              >
                {{
                  userSessionRevokingId === session.id ? "撤销中…" : "撤销会话"
                }}
              </button>
            </div>
          </div>
        </template>
      </div>
    </aside>
  </div>
</template>
