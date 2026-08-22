<script setup lang="ts">
import { useAdminApps } from "../../composables/admin/useAdminApps";
import AdminAppDrawer from "./AdminAppDrawer.vue";
import AdminAppModals from "./AdminAppModals.vue";

const {
  appsLoading,
  appsError,
  appQuery,
  appPage,
  filteredApps,
  appPages,
  appPageItems,
  appModalOpen,
  resetAppForm,
  loadApps,
  openApp,
} = useAdminApps();

function formatMode(mode: string) {
  return (
    (
      {
        Disabled: "关闭",
        ManualApproval: "人工准入",
        AutoProvision: "自动开户",
        BindRequired: "需绑定",
      } as Record<string, string>
    )[mode] ?? mode
  );
}
</script>

<template>
  <section class="console-view">
    <div class="console-page-heading">
      <div>
        <h1>应用管理</h1>
        <p>管理应用注册、回调地址、登录准入和换票信任。</p>
      </div>
      <div class="heading-actions">
        <button
          class="console-button primary"
          @click="
            resetAppForm();
            appModalOpen = true;
          "
        >
          ＋ 注册应用
        </button>
      </div>
    </div>
    <article class="console-panel list-panel">
      <div class="filter-bar">
        <div class="console-search wide">
          <span>⌕</span
          ><input
            v-model="appQuery.search"
            placeholder="搜索应用名称、App ID 或回调地址"
          />
        </div>
        <select
          v-model="appQuery.status"
          class="console-select"
          aria-label="应用状态"
        >
          <option value="all">全部状态</option>
          <option value="active">已启用</option>
          <option value="disabled">已停用</option></select
        ><select
          v-model="appQuery.mode"
          class="console-select"
          aria-label="准入策略"
        >
          <option value="all">所有准入策略</option>
          <option value="ManualApproval">人工准入</option>
          <option value="AutoProvision">自动开户</option>
          <option value="BindRequired">需绑定</option>
          <option value="Disabled">关闭</option>
        </select>
      </div>
      <div v-if="appsLoading" class="console-table-state">
        <span class="console-spinner"></span>读取应用目录…
      </div>
      <div v-else-if="appsError" class="console-table-state error">
        {{ appsError }}
        <button class="text-button" @click="loadApps">重试</button>
      </div>
      <div v-else-if="!appPageItems.length" class="console-table-state">
        <span class="big-state-icon">▦</span><b>没有匹配应用</b
        ><small>调整搜索条件或注册一个新的接入资源。</small>
      </div>
      <div v-else class="console-table-scroll">
        <table class="console-table resource-table">
          <thead>
            <tr>
              <th>应用资源</th>
              <th>回调与受众</th>
              <th>登录准入</th>
              <th>状态</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="app in appPageItems"
              :key="app.appId"
              tabindex="0"
              @click="openApp(app)"
              @keydown.enter="openApp(app)"
            >
              <td>
                <div class="table-primary">
                  <span class="resource-glyph">▦</span
                  ><span
                    ><b>{{ app.appName }}</b
                    ><small class="mono">{{ app.appId }}</small></span
                  >
                </div>
              </td>
              <td>
                <span class="mono truncate">{{
                  app.callbackUrl || "未配置回调"
                }}</span
                ><small class="table-secondary">aud: {{ app.audience }}</small>
              </td>
              <td>
                <div class="strategy-stack">
                  <span>{{ formatMode(app.ldapLoginMode) }} LDAP</span
                  ><span>{{ formatMode(app.smsLoginMode) }} 短信</span
                  ><span>{{ formatMode(app.wechatLoginMode) }} 微信</span>
                </div>
              </td>
              <td>
                <span
                  class="status-pill"
                  :class="app.isActive ? 'green' : 'gray'"
                  ><i></i>{{ app.isActive ? "已启用" : "已停用" }}</span
                >
              </td>
              <td class="row-arrow">→</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="console-pager">
        <span
          >显示 {{ appPageItems.length }} /
          {{ filteredApps.length }} 个匹配应用</span
        ><button :disabled="appPage <= 1" @click="appPage--">←</button
        ><button :disabled="appPage >= appPages" @click="appPage++">→</button>
      </div>
    </article>
    <div class="console-info-band">
      <span>ⓘ</span>
      <p>
        App Secret 只在注册或重置时返回一次。该页面不会把 Secret
        写入本地存储，关闭一次性凭据窗口前需要明确确认。
      </p>
    </div>
  </section>
  <AdminAppDrawer />
  <AdminAppModals />
</template>
