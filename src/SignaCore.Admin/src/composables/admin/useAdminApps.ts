import { computed, reactive, ref, watch } from "vue";
import { adminClient } from "../../services/apiClient";
import { getErrorMessage, type AdminApp } from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { notify } from "./useAdminFeedback";
import { useAdminAppAccess } from "./useAdminAppAccess";

export type AppTab = "overview" | "access" | "trust" | "danger";
export type AppActionModal = "secret" | "reset-secret" | "delete-app" | null;

const apps = ref<AdminApp[]>([]);
const appsLoading = ref(false);
const appsError = ref("");
const appQuery = reactive({
  search: "",
  status: "all" as "all" | "active" | "disabled",
  mode: "all",
});
const appPage = ref(1);
const appPageSize = 8;
const selectedApp = ref<AdminApp | null>(null);
const appDrawerOpen = ref(false);
const appTab = ref<AppTab>("overview");
const appSaving = ref(false);
const appConfig = reactive({
  callbackUrl: "",
  ttlSeconds: 86400,
  isActive: true,
  ldapLoginMode: "Disabled" as AdminApp["ldapLoginMode"],
  smsLoginMode: "Disabled" as AdminApp["smsLoginMode"],
  smsProfileKey: "",
  wechatLoginMode: "Disabled" as AdminApp["wechatLoginMode"],
  audienceMode: "Shared" as AdminApp["audienceMode"],
});
const appAccess = useAdminAppAccess(selectedApp);
const appModalOpen = ref(false);
const appSavingNew = ref(false);
const createAppForm = reactive({
  appName: "",
  callbackUrl: "",
  ttlSeconds: 86400,
});
const appActionModal = ref<AppActionModal>(null);
const secretValue = ref("");
const secretAcknowledged = ref(false);
const deleteConfirmId = ref("");
const destructiveBusy = ref(false);

const filteredApps = computed(() =>
  apps.value.filter((app) => {
    const search = appQuery.search.trim().toLowerCase();
    const textMatches =
      !search ||
      `${app.appName} ${app.appId} ${app.callbackUrl}`
        .toLowerCase()
        .includes(search);
    const statusMatches =
      appQuery.status === "all" ||
      (appQuery.status === "active" ? app.isActive : !app.isActive);
    const modeMatches =
      appQuery.mode === "all" ||
      app.ldapLoginMode === appQuery.mode ||
      app.smsLoginMode === appQuery.mode ||
      app.wechatLoginMode === appQuery.mode;
    return textMatches && statusMatches && modeMatches;
  }),
);
const appPages = computed(() =>
  Math.max(1, Math.ceil(filteredApps.value.length / appPageSize)),
);
const appPageItems = computed(() =>
  filteredApps.value.slice(
    (appPage.value - 1) * appPageSize,
    appPage.value * appPageSize,
  ),
);
function resetAppForm() {
  Object.assign(createAppForm, {
    appName: "",
    callbackUrl: "",
    ttlSeconds: 86400,
  });
}

async function loadApps() {
  appsLoading.value = true;
  appsError.value = "";
  try {
    apps.value = await adminClient.getApps();
    if (appPage.value > appPages.value) appPage.value = 1;
  } catch (error) {
    appsError.value = getErrorMessage(error);
    handleApiError("加载应用目录失败", error);
  } finally {
    appsLoading.value = false;
  }
}

function syncAppForm(app: AdminApp) {
  Object.assign(appConfig, {
    callbackUrl: app.callbackUrl || "",
    ttlSeconds: app.callbackExpiresAt
      ? Math.max(1, app.callbackExpiresAt - Math.floor(Date.now() / 1000))
      : 86400,
    isActive: app.isActive,
    ldapLoginMode: app.ldapLoginMode,
    smsLoginMode: app.smsLoginMode,
    smsProfileKey: app.smsProfileKey || "",
    wechatLoginMode: app.wechatLoginMode,
    audienceMode: app.audienceMode,
  });
}

async function openApp(app: AdminApp) {
  selectedApp.value = app;
  appTab.value = "overview";
  syncAppForm(app);
  appDrawerOpen.value = true;
  await appAccess.loadAppDetails(app.appId);
}

async function saveAppConfig() {
  if (!selectedApp.value) return;
  appSaving.value = true;
  try {
    await adminClient.updateCallback(selectedApp.value.appId, {
      callbackUrl: appConfig.callbackUrl.trim() || undefined,
      ttlSeconds: Math.max(0, Number(appConfig.ttlSeconds) || 0),
      isActive: appConfig.isActive,
    });
    await adminClient.updateLdapPolicy(
      selectedApp.value.appId,
      appConfig.ldapLoginMode,
    );
    await adminClient.updateSmsPolicy(
      selectedApp.value.appId,
      appConfig.smsLoginMode,
      appConfig.smsProfileKey || null,
    );
    await adminClient.updateWechatPolicy(
      selectedApp.value.appId,
      appConfig.wechatLoginMode,
    );
    await adminClient.updateAudienceMode(
      selectedApp.value.appId,
      appConfig.audienceMode,
    );
    notify("应用配置已保存");
    await loadApps();
    selectedApp.value =
      apps.value.find((app) => app.appId === selectedApp.value?.appId) ??
      selectedApp.value;
    if (selectedApp.value) syncAppForm(selectedApp.value);
  } catch (error) {
    handleApiError("保存应用配置失败，已完成的单项可能已生效", error);
    await loadApps();
  } finally {
    appSaving.value = false;
  }
}

async function createApp() {
  if (!createAppForm.appName.trim() || Number(createAppForm.ttlSeconds) < 0)
    return notify("请输入应用名称和有效的回调 TTL");
  appSavingNew.value = true;
  try {
    const created = await adminClient.createApp({
      appName: createAppForm.appName.trim(),
      callbackUrl: createAppForm.callbackUrl.trim() || undefined,
      ttlSeconds: Math.max(0, Number(createAppForm.ttlSeconds) || 0),
    });
    appModalOpen.value = false;
    secretValue.value = created.appSecret;
    secretAcknowledged.value = false;
    appActionModal.value = "secret";
    resetAppForm();
    await loadApps();
  } catch (error) {
    handleApiError("注册应用失败", error);
  } finally {
    appSavingNew.value = false;
  }
}

async function resetAppSecret() {
  if (!selectedApp.value) return;
  destructiveBusy.value = true;
  try {
    const result = await adminClient.resetAppSecret(selectedApp.value.appId);
    secretValue.value = result.appSecret;
    secretAcknowledged.value = false;
    appActionModal.value = "secret";
    notify("新 Secret 已生成，旧 Secret 已失效");
  } catch (error) {
    handleApiError("重置 Secret 失败", error);
  } finally {
    destructiveBusy.value = false;
  }
}

async function deleteApp() {
  if (
    !selectedApp.value ||
    deleteConfirmId.value.trim() !== selectedApp.value.appId
  )
    return;
  destructiveBusy.value = true;
  try {
    await adminClient.deleteApp(selectedApp.value.appId);
    notify("应用已删除，当前后端没有恢复接口");
    closeAppDrawer();
    appActionModal.value = null;
    await loadApps();
  } catch (error) {
    handleApiError("删除应用失败", error);
  } finally {
    destructiveBusy.value = false;
  }
}

function closeAppDrawer() {
  appDrawerOpen.value = false;
  selectedApp.value = null;
  appAccess.clearAccess();
}
function closeActionModal() {
  if (appActionModal.value === "secret" && !secretAcknowledged.value)
    return notify("请确认已安全保存 Secret 后关闭");
  appActionModal.value = null;
  deleteConfirmId.value = "";
}
function copySecret() {
  if (!secretValue.value) return;
  if (navigator.clipboard && window.isSecureContext)
    void navigator.clipboard
      .writeText(secretValue.value)
      .then(() => notify("Secret 已复制"));
  else notify("当前环境不支持自动复制，请手动选择");
}

watch(
  () => appQuery.search + appQuery.status + appQuery.mode,
  () => {
    appPage.value = 1;
  },
);

export function useAdminApps() {
  return {
    apps,
    appsLoading,
    appsError,
    appQuery,
    appPage,
    filteredApps,
    appPages,
    appPageItems,
    selectedApp,
    appDrawerOpen,
    appTab,
    appSaving,
    appConfig,
    ...appAccess,
    appModalOpen,
    appSavingNew,
    createAppForm,
    appActionModal,
    secretValue,
    secretAcknowledged,
    deleteConfirmId,
    destructiveBusy,
    loadApps,
    resetAppForm,
    openApp,
    saveAppConfig,
    createApp,
    resetAppSecret,
    deleteApp,
    closeAppDrawer,
    closeActionModal,
    copySecret,
  };
}
