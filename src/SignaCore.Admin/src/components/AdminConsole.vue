<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { appTitle, handleLogout, session } from "../composables/useSession";
import { useAdminFeedback } from "../composables/admin/useAdminFeedback";
import { useAdminApps } from "../composables/admin/useAdminApps";
import { useAdminSecurity } from "../composables/admin/useAdminSecurity";
import {
  adminSettingsSections,
  useAdminSettings,
  type SettingsSectionKey,
} from "../composables/admin/useAdminSettings";
import { useAdminUsers } from "../composables/admin/useAdminUsers";
import { getInitials } from "../utils/format";
import AdminIdentityView from "./admin/AdminIdentityView.vue";
import AdminOverviewView from "./admin/AdminOverviewView.vue";
import AdminResourcesView from "./admin/AdminResourcesView.vue";
import AdminSecurityView from "./admin/AdminSecurityView.vue";
import AdminSettingsView from "./admin/AdminSettingsView.vue";
import AdminTokenModal from "./admin/AdminTokenModal.vue";

type ViewKey =
  | "overview"
  | "identity"
  | "resources"
  | "security"
  | SettingsSectionKey;
type NavItem = { key: ViewKey; label: string; mark: string };

const settingsNavItems: NavItem[] = adminSettingsSections.map(
  (section, index) => ({
    key: section.key,
    label: section.label,
    mark: ["◌", "◇", "▣", "⌁", "∿", "◈", "◎", "≋", "◍", "▤"][index] ?? "·",
  }),
);

const navGroups: { label: string; items: NavItem[] }[] = [
  {
    label: "管理",
    items: [
      { key: "overview", label: "概览", mark: "◈" },
      { key: "identity", label: "用户管理", mark: "◎" },
      { key: "resources", label: "应用管理", mark: "▦" },
    ],
  },
  {
    label: "安全",
    items: [
      { key: "security", label: "审计日志", mark: "⌁" },
    ],
  },
  { label: "系统配置", items: settingsNavItems },
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

const activeSettingsSection = computed<SettingsSectionKey>(() =>
  adminSettingsSections.some((section) => section.key === activeView.value)
    ? (activeView.value as SettingsSectionKey)
    : "settings-identity",
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
          <strong>{{ appTitle }}</strong>
        </div>
      </div>
      <nav class="console-nav">
        <div
          v-for="group in navGroups"
          :key="group.label"
          class="console-nav-group"
          :class="{ 'settings-menu-group': group.label === '系统配置' }"
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
            ><span class="console-nav-copy"><b>{{ item.label }}</b></span>
          </button>
        </div>
      </nav>
      <div class="console-sidebar-footer">
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
          <strong>{{ activeNavLabel }}</strong>
        </div>
        <div class="console-header-actions">
          <button
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
            v-else
            :section="activeSettingsSection"
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
    <AdminTokenModal />
  </div>
</template>
