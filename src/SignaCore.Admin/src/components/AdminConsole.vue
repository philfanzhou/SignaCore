<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { appTitle, handleLogout, session } from "../composables/useSession";
import { useAdminFeedback } from "../composables/admin/useAdminFeedback";
import { useAdminApps } from "../composables/admin/useAdminApps";
import { useAdminSecurity } from "../composables/admin/useAdminSecurity";
import { useAdminSettings } from "../composables/admin/useAdminSettings";
import { useAdminUsers } from "../composables/admin/useAdminUsers";
import { getInitials } from "../utils/format";
import AdminBoundaryView from "./admin/AdminBoundaryView.vue";
import AdminIdentityView from "./admin/AdminIdentityView.vue";
import AdminOverviewView from "./admin/AdminOverviewView.vue";
import AdminResourcesView from "./admin/AdminResourcesView.vue";
import AdminSecurityView from "./admin/AdminSecurityView.vue";
import AdminSettingsView from "./admin/AdminSettingsView.vue";

type ViewKey =
  | "overview"
  | "identity"
  | "resources"
  | "security"
  | "settings"
  | "boundary";
type NavItem = { key: ViewKey; label: string; mark: string; hint: string };

const navGroups: { label: string; items: NavItem[] }[] = [
  {
    label: "工作台",
    items: [
      { key: "overview", label: "运行总览", mark: "◈", hint: "状态与待办" },
    ],
  },
  {
    label: "身份目录",
    items: [
      { key: "identity", label: "账户目录", mark: "◎", hint: "用户与登录历史" },
    ],
  },
  {
    label: "接入资源",
    items: [
      {
        key: "resources",
        label: "应用与策略",
        mark: "▦",
        hint: "OAuth 与身份源",
      },
    ],
  },
  {
    label: "安全中心",
    items: [
      {
        key: "security",
        label: "审计与会话",
        mark: "⌁",
        hint: "操作记录与撤销",
      },
    ],
  },
  {
    label: "系统",
    items: [
      { key: "settings", label: "运行配置", mark: "◌", hint: "配置版本与引导" },
      { key: "boundary", label: "能力边界", mark: "△", hint: "当前版本说明" },
    ],
  },
];

const activeView = ref<ViewKey>("overview");
const navOpen = ref(false);
const sessionModalOpen = ref(false);
const initialLoading = ref(true);
const consoleError = ref("");
const { toast } = useAdminFeedback();
const usersDomain = useAdminUsers();
const appsDomain = useAdminApps();
const securityDomain = useAdminSecurity();
const settingsDomain = useAdminSettings();

const activeNavLabel = computed(
  () =>
    navGroups
      .flatMap((group) => group.items)
      .find((item) => item.key === activeView.value)?.label ?? "运行总览",
);

function navigate(view: ViewKey) {
  activeView.value = view;
  navOpen.value = false;
  sessionModalOpen.value = false;
  if (view === "security" && !securityDomain.auditLogs.value.length)
    void securityDomain.loadAuditLogs();
}

async function loadInitial() {
  initialLoading.value = true;
  consoleError.value = "";
  const results = await Promise.allSettled([
    usersDomain.loadUsers(),
    appsDomain.loadApps(),
    settingsDomain.loadSettings(),
    settingsDomain.loadBootstrap(),
  ]);
  if (results.every((result) => result.status === "rejected"))
    consoleError.value = "核心管理数据暂时无法加载，请检查会话和服务状态。";
  initialLoading.value = false;
}

function onKeydown(event: KeyboardEvent) {
  if (event.key !== "Escape") return;
  if (sessionModalOpen.value) sessionModalOpen.value = false;
  else if (securityDomain.tokenModalOpen.value)
    securityDomain.closeTokenModal();
  else if (appsDomain.appActionModal.value) appsDomain.closeActionModal();
  else if (appsDomain.appModalOpen.value) appsDomain.appModalOpen.value = false;
  else if (appsDomain.appDrawerOpen.value) appsDomain.closeAppDrawer();
  else if (usersDomain.userModalOpen.value)
    usersDomain.userModalOpen.value = false;
  else if (usersDomain.userDrawerOpen.value) usersDomain.closeUserDrawer();
  else navOpen.value = false;
}

onMounted(() => {
  window.addEventListener("keydown", onKeydown);
  void loadInitial();
});
onUnmounted(() => {
  window.removeEventListener("keydown", onKeydown);
});
</script>

<template>
  <div class="console-shell">
    <aside
      class="console-sidebar"
      :class="{ open: navOpen }"
      aria-label="管理端主导航"
    >
      <div class="console-brand">
        <div class="console-brand-mark">SC</div>
        <div>
          <strong>{{ appTitle }}</strong
          ><span>Identity operations</span>
        </div>
      </div>
      <nav class="console-nav">
        <div
          v-for="group in navGroups"
          :key="group.label"
          class="console-nav-group"
        >
          <div class="console-nav-label">{{ group.label }}</div>
          <button
            v-for="item in group.items"
            :key="item.key"
            class="console-nav-item"
            :class="{ active: activeView === item.key }"
            :aria-current="activeView === item.key ? 'page' : undefined"
            @click="navigate(item.key)"
          >
            <span class="console-nav-mark" aria-hidden="true">{{
              item.mark
            }}</span
            ><span class="console-nav-copy"
              ><b>{{ item.label }}</b
              ><small>{{ item.hint }}</small></span
            >
          </button>
        </div>
      </nav>
      <div class="console-sidebar-footer">
        <div class="console-signal"><span></span>管理会话已建立</div>
        <button class="console-account-mini" @click="sessionModalOpen = true">
          <span class="console-avatar">{{
            getInitials(session?.username || "A").slice(0, 2)
          }}</span
          ><span
            ><b>{{ session?.username || "管理员" }}</b
            ><small>配置管理员</small></span
          ><span class="console-more">•••</span>
        </button>
      </div>
    </aside>
    <div v-if="navOpen" class="console-backdrop" @click="navOpen = false"></div>
    <section class="console-main">
      <header class="console-header">
        <button
          class="console-menu-button"
          aria-label="打开导航"
          @click="navOpen = !navOpen"
        >
          ☰
        </button>
        <div class="console-location">
          <span>SignaCore /</span><strong>{{ activeNavLabel }}</strong>
        </div>
        <div class="console-header-actions">
          <span class="console-environment"><i></i>内部环境</span
          ><button
            class="console-header-icon"
            title="刷新当前数据"
            @click="loadInitial"
          >
            ↻</button
          ><button class="console-user-button" @click="sessionModalOpen = true">
            <span class="console-avatar small">{{
              getInitials(session?.username || "A").slice(0, 2)
            }}</span
            ><span class="console-user-name">{{
              session?.username || "管理员"
            }}</span
            ><span>⌄</span>
          </button>
        </div>
      </header>
      <main class="console-content">
        <div v-if="initialLoading" class="console-loading-page" role="status">
          <span class="console-spinner"></span>
          <p>正在读取管理目录…</p>
        </div>
        <div v-else-if="consoleError" class="console-state error-state">
          <div class="console-state-icon">!</div>
          <h2>管理数据不可用</h2>
          <p>{{ consoleError }}</p>
          <button class="console-button primary" @click="loadInitial">
            重新加载
          </button>
        </div>
        <template v-else
          ><AdminOverviewView
            v-if="activeView === 'overview'"
            :navigate="navigate" /><AdminIdentityView
            v-else-if="activeView === 'identity'" /><AdminResourcesView
            v-else-if="activeView === 'resources'" /><AdminSecurityView
            v-else-if="activeView === 'security'" /><AdminSettingsView
            v-else-if="activeView === 'settings'" /><AdminBoundaryView v-else
        /></template>
      </main>
    </section>

    <div
      v-if="sessionModalOpen"
      class="console-modal-layer"
      @click.self="sessionModalOpen = false"
    >
      <section
        class="console-modal session-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="session-title"
      >
        <div class="modal-header">
          <div>
            <span class="console-eyebrow">ADMIN SESSION</span>
            <h2 id="session-title">当前管理会话</h2>
          </div>
          <button
            class="close-button"
            aria-label="关闭"
            @click="sessionModalOpen = false"
          >
            ×
          </button>
        </div>
        <div class="modal-body">
          <div class="session-card">
            <span class="console-avatar large">{{
              getInitials(session?.username || "A").slice(0, 2)
            }}</span>
            <div>
              <b>{{ session?.username || "管理员" }}</b>
              <p>AdminSession · Cookie 会话</p>
            </div>
            <span class="status-pill green"><i></i>有效</span>
          </div>
          <p class="panel-note">
            退出会话会清理当前浏览器的管理状态，并回到登录页。
          </p>
        </div>
        <div class="modal-footer">
          <button
            class="console-button secondary"
            @click="sessionModalOpen = false"
          >
            继续管理</button
          ><button
            class="console-button danger"
            @click="
              sessionModalOpen = false;
              handleLogout();
            "
          >
            退出登录
          </button>
        </div>
      </section>
    </div>
    <div v-if="toast" class="console-toast" role="status">{{ toast }}</div>
  </div>
</template>
