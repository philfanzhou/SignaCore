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
  allVisibleAppsSelected,
  selectedAppIds,
  appModalOpen,
  resetAppForm,
  loadApps,
  openApp,
  toggleAppSelection,
  toggleVisibleApps,
  showUnsupported,
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
        <p class="console-eyebrow">RESOURCE REGISTRY</p>
        <h1>应用与策略</h1>
        <p>以应用为边界集中管理回调、登录准入、换票信任和生命周期。</p>
      </div>
      <div class="heading-actions">
        <button
          class="console-button ghost"
          @click="showUnsupported('应用列表服务端分页与导出')"
        >
          导出说明</button
        ><button
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
      <div class="batch-strip" :class="{ active: selectedAppIds.length }">
        <span>{{
          selectedAppIds.length
            ? `已选择 ${selectedAppIds.length} 个应用`
            : "选择应用后可查看批量能力边界"
        }}</span
        ><button
          v-if="selectedAppIds.length"
          class="console-button ghost compact"
          @click="showUnsupported('应用批量启停、批量删除和导出')"
        >
          批量操作</button
        ><span v-else class="panel-note">当前后端只提供单应用操作</span>
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
              <th class="check-col">
                <input
                  type="checkbox"
                  :checked="allVisibleAppsSelected"
                  aria-label="选择当前页"
                  @change="toggleVisibleApps"
                />
              </th>
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
              <td class="check-col" @click.stop>
                <input
                  type="checkbox"
                  :checked="selectedAppIds.includes(app.appId)"
                  :aria-label="`选择 ${app.appName}`"
                  @change="toggleAppSelection(app.appId)"
                />
              </td>
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
