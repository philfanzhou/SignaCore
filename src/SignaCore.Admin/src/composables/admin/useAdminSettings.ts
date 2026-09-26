import { computed, reactive, ref } from "vue";
import axios from "axios";
import { adminClient } from "../../services/apiClient";
import {
  getErrorMessage,
  type AdminSettingChange,
  type AdminSettingValue,
  type BootstrapSettings,
  type BootstrapTestPayload,
  type BootstrapUpdatePayload,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { bootstrapProviderCatalog } from "../../utils/bootstrapProviders";
import {
  buildPostgreSqlConnectionString,
  buildSqliteConnectionString,
} from "../../utils/bootstrapConnectionString";
import { notify } from "./useAdminFeedback";

export type SettingsSectionKey =
  | "settings-identity"
  | "settings-admin"
  | "settings-network"
  | "settings-sms"
  | "settings-wechat"
  | "settings-ldap"
  | "settings-observability"
  | "settings-consul"
  | "settings-bootstrap";

export type AdminSettingsSection = {
  key: SettingsSectionKey;
  label: string;
  description: string;
  /** 归一化键前缀（key === prefix 或 key 以 prefix + "." 开头）。 */
  prefixes?: string[];
};

export const adminSettingsSections: AdminSettingsSection[] = [
  {
    key: "settings-identity",
    label: "域名与令牌",
    description: "配置公开地址、JWT、刷新令牌及密码哈希策略。",
    prefixes: ["endpoints", "jwt", "refresh_token", "password_hasher", "security"],
  },
  {
    key: "settings-admin",
    label: "管理端",
    description: "配置管理端允许的来源和初始管理员标识。",
    prefixes: ["admin", "admin_web"],
  },
  {
    key: "settings-network",
    label: "回调与代理",
    description: "配置回调地址边界和反向代理可信来源。",
    prefixes: ["callback", "reverse_proxy"],
  },
  {
    key: "settings-sms",
    label: "短信登录",
    description: "配置短信验证码限制、绕过规则和短信服务档案。",
    prefixes: ["sms"],
  },
  {
    key: "settings-wechat",
    label: "微信登录",
    description: "配置微信应用标识、密钥和接口地址。",
    prefixes: ["wechat"],
  },
  {
    key: "settings-ldap",
    label: "LDAP 目录",
    description: "配置 LDAP 开关、默认目录和目录连接信息。",
    prefixes: ["ldap"],
  },
  {
    key: "settings-observability",
    label: "日志与监控",
    description: "配置 Loki 上报地址与授权头，以及 OpenTelemetry 上报地址。",
    prefixes: ["loki", "opentelemetry"],
  },
  {
    key: "settings-consul",
    label: "服务发现",
    description: "配置 Consul 连接和服务注册发现行为。",
    prefixes: ["consul"],
  },
  {
    key: "settings-bootstrap",
    label: "数据库引导",
    description: "切换当前实例的引导数据库目标；操作会重启服务。",
  },
];

const settings = ref<AdminSettingValue[]>([]);
const settingsLoading = ref(false);
const settingsSaving = ref(false);
const settingsError = ref("");
const settingsDraft = reactive<Record<string, string>>({});
/** 本次加载快照的存储版本；null 表示超出 JS 安全整数范围，无法精确表达，禁止提交。 */
const configurationVersion = ref<number | null>(null);
/** 本进程启动时激活的运行版本，来自产品响应头；null 表示未知，绝不推断为已生效。 */
const runningConfigurationVersion = ref<number | null>(null);
const bootstrapSettings = ref<BootstrapSettings | null>(null);
const bootstrapLoading = ref(false);
const bootstrapSaving = ref(false);
const bootstrapTesting = ref(false);
const bootstrapRestarting = ref(false);
const bootstrapMessage = ref("");
const bootstrapError = ref("");
const bootstrapForm = reactive({
  provider: "",
  serverVersion: "",
  endpoint: "",
  filePath: "",
  host: "",
  port: "",
  database: "",
  username: "",
  password: "",
  connectionString: "",
  masterKey: "",
  confirm: false,
});

const changedSettings = computed(() =>
  settings.value.filter((setting) => {
    if (!(setting.key in settingsDraft)) return false;
    const value = settingsDraft[setting.key] ?? "";
    // 敏感值不回显：空草稿表示"不修改"，绝不转成 null（null 是"移除显式值"）。
    return setting.isSensitive
      ? value.trim().length > 0
      : value !== (setting.value ?? "");
  }),
);
const settingGroups = computed(() => {
  const map = new Map<string, AdminSettingValue[]>();
  for (const setting of settings.value) {
    const prefix = setting.key.split(".")[0] || "其他";
    map.set(prefix, [...(map.get(prefix) ?? []), setting]);
  }
  return [...map.entries()].map(([name, items]) => ({ name, items }));
});
/** 两个版本都已知且不相等才算"待重启"；任一未知都不推断。 */
const restartPending = computed(
  () =>
    configurationVersion.value !== null &&
    runningConfigurationVersion.value !== null &&
    configurationVersion.value !== runningConfigurationVersion.value,
);
const hasBootstrapForm = computed(() =>
  Boolean(bootstrapSettings.value?.editable),
);

function getSettingsSection(key: SettingsSectionKey) {
  return adminSettingsSections.find((section) => section.key === key)!;
}

function getSettingsForSection(key: SettingsSectionKey) {
  const section = getSettingsSection(key);
  if (!section.prefixes) return [];
  return settings.value.filter((setting) =>
    section.prefixes?.some(
      (prefix) => setting.key === prefix || setting.key.startsWith(`${prefix}.`),
    ),
  );
}

function formatValue(setting: AdminSettingValue) {
  if (setting.isSensitive)
    return setting.hasValue ? "已配置（不会回显）" : "未配置";
  if (setting.valueType === "boolean")
    return setting.value === "true" ? "启用" : "停用";
  return setting.value || "空";
}

async function loadSettings() {
  settingsLoading.value = true;
  settingsError.value = "";
  try {
    const { snapshot, runningVersion } = await adminClient.getSettings();
    settings.value = snapshot.values;
    configurationVersion.value = snapshot.version;
    runningConfigurationVersion.value = runningVersion;
    for (const key of Object.keys(settingsDraft)) delete settingsDraft[key];
    for (const setting of snapshot.values)
      if (!setting.isSensitive) settingsDraft[setting.key] = setting.value ?? "";
  } catch (error) {
    settingsError.value = getErrorMessage(error);
    handleApiError("加载运行配置失败", error);
  } finally {
    settingsLoading.value = false;
  }
}

async function saveSettings(keys?: string[]) {
  if (configurationVersion.value === null) {
    notify("配置版本超出可精确表达的范围，无法安全提交；请刷新页面核对。");
    return;
  }
  const keySet = keys ? new Set(keys) : null;
  const pending = changedSettings.value.filter(
    (setting) => !keySet || keySet.has(setting.key),
  );
  if (!pending.length) return;
  const savedKeys = new Set(pending.map((setting) => setting.key));
  const draftsToPreserve = new Map(
    changedSettings.value
      .filter((setting) => !savedKeys.has(setting.key))
      .map((setting) => [setting.key, settingsDraft[setting.key] ?? ""]),
  );
  settingsSaving.value = true;
  try {
    const changes: AdminSettingChange[] = pending.map((setting) => ({
      key: setting.key,
      value: settingsDraft[setting.key] ?? "",
    }));
    const result = await adminClient.updateSettings(
      configurationVersion.value,
      changes,
    );
    notify(`设置已保存（版本 v${result.version}）；重启实例后生效。`);
    await loadSettings();
    const availableKeys = new Set(settings.value.map((setting) => setting.key));
    for (const [key, value] of draftsToPreserve)
      if (availableKeys.has(key)) settingsDraft[key] = value;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 409) {
      // 版本冲突：保留草稿，提示刷新核对，禁止自动覆盖重试。
      notify("配置已被其他会话修改（版本冲突）。草稿已保留，请刷新核对后再提交。");
    } else {
      handleApiError("保存运行配置失败", error);
    }
  } finally {
    settingsSaving.value = false;
  }
}

function discardSettings(keys?: string[]) {
  const keySet = keys ? new Set(keys) : null;
  for (const setting of settings.value) {
    if (keySet && !keySet.has(setting.key)) continue;
    settingsDraft[setting.key] = setting.isSensitive ? "" : (setting.value ?? "");
  }
  notify("已撤销未保存修改");
}

async function loadBootstrap() {
  bootstrapLoading.value = true;
  try {
    const result = await adminClient.getBootstrapSettings();
    bootstrapSettings.value = result;
    Object.assign(bootstrapForm, {
      provider: result.provider,
      serverVersion: result.serverVersion ?? "",
      endpoint: result.endpoint,
      filePath: result.filePath,
    });
  } catch (error) {
    bootstrapError.value = getErrorMessage(error);
  } finally {
    bootstrapLoading.value = false;
  }
}

/** The provider list is the one fixed catalog shared with the first-install form. */
function bootstrapProviderList() {
  return bootstrapProviderCatalog;
}

/**
 * The shared update entry accepts only a complete connection string: the advanced field wins when
 * set, otherwise the structured fields are assembled through the shared quoting helper so every
 * character survives the provider parser verbatim.
 */
function assembleConnectionString(): string {
  const advanced = bootstrapForm.connectionString.trim();
  if (advanced) return advanced;
  if (bootstrapForm.provider === "SQLite") {
    return buildSqliteConnectionString(bootstrapForm.filePath.trim());
  }
  return buildPostgreSqlConnectionString({
    host: bootstrapForm.host.trim(),
    port: bootstrapForm.port ? Number(bootstrapForm.port) : null,
    database: bootstrapForm.database.trim(),
    username: bootstrapForm.username.trim(),
    password: bootstrapForm.password,
  });
}

/** An empty key omits the property — the shared entry treats omission as "keep the current key". */
function bootstrapUpdatePayload(): BootstrapUpdatePayload {
  const payload: BootstrapUpdatePayload = {
    database: {
      provider: bootstrapForm.provider,
      serverVersion:
        bootstrapForm.provider === "SQLite" ? null : bootstrapForm.serverVersion.trim() || null,
      connectionString: assembleConnectionString(),
    },
  };
  const key = bootstrapForm.masterKey.trim();
  if (key) payload.masterKey = key;
  return payload;
}

/** The probe keeps the structured body; a blank key means "test against the running one". */
function bootstrapTestPayload(): BootstrapTestPayload {
  return {
    database: {
      provider: bootstrapForm.provider,
      serverVersion:
        bootstrapForm.provider === "SQLite" ? null : bootstrapForm.serverVersion.trim() || null,
      host: bootstrapForm.host.trim() || undefined,
      port: bootstrapForm.port ? Number(bootstrapForm.port) : null,
      database: bootstrapForm.database.trim() || undefined,
      username: bootstrapForm.username.trim() || undefined,
      password: bootstrapForm.password || undefined,
      filePath: bootstrapForm.filePath.trim() || undefined,
      connectionString: bootstrapForm.connectionString.trim() || undefined,
    },
    masterKey: bootstrapForm.masterKey.trim() || null,
  };
}

/** Maps the closed rejection set of the shared entry and the two SignaCore guard codes. */
function bootstrapUpdateMessageFrom(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;
    const errorCode = (error.response?.data as { errorCode?: string } | undefined)?.errorCode;
    if (status === 401) return "登录状态无效，请重新登录。";
    if (status === 403) return "当前账号没有管理后台访问权限。";
    if (errorCode === "signacore.bootstrap.confirmation_required")
      return "换库前必须勾选确认；本次请求没有改变任何文件。";
    if (errorCode === "signacore.bootstrap.not_file_backed")
      return "当前实例不是从引导文件启动的，不能在这里换库。";
    if (status === 503) return "服务暂时无法完成请求，请稍后重试。";
  }
  return getErrorMessage(error);
}

async function testBootstrapSettings() {
  if (!bootstrapForm.confirm)
    return notify("测试前请确认你理解数据库目标切换影响");
  bootstrapTesting.value = true;
  bootstrapError.value = "";
  try {
    const result = await adminClient.testBootstrapSettings(bootstrapTestPayload());
    bootstrapMessage.value = `${result.message} 目标：${result.endpoint}`;
  } catch (error) {
    bootstrapError.value = getErrorMessage(error);
  } finally {
    bootstrapTesting.value = false;
  }
}

/**
 * After a committed update the instance restarts. The normal host does not map the installation
 * status entry, so recovery watches liveness: once /health/live has been observed unavailable,
 * the first 200 again means the restart completed and the console reloads — into a fresh login if
 * the new target holds a different key ring. Five minutes without a restart fall back to a
 * manual instruction.
 */
async function waitForRestartAfterUpdate() {
  bootstrapRestarting.value = true;
  const startedAt = Date.now();
  let observedDown = false;
  for (;;) {
    try {
      const response = await axios.get("/health/live", {
        timeout: 3000,
        validateStatus: () => true,
      });
      if (observedDown && response.status === 200) {
        window.location.assign("/admin");
        return;
      }
      if (response.status !== 200) observedDown = true;
    } catch {
      observedDown = true;
    }

    if (Date.now() - startedAt > 5 * 60 * 1000) {
      bootstrapRestarting.value = false;
      bootstrapError.value =
        "服务在五分钟内没有完成重启。请手动重启实例后刷新本页；如新目标使用不同的密钥环，需要重新登录。";
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

async function saveBootstrapSettings() {
  if (!bootstrapForm.confirm) return notify("保存前必须明确确认，服务会重启");
  bootstrapSaving.value = true;
  bootstrapError.value = "";
  try {
    const result = await adminClient.updateBootstrapSettings(bootstrapUpdatePayload());
    if (!result.restartRequired) {
      bootstrapError.value = "服务返回了意外的更新结果，请刷新后检查实例状态。";
      return;
    }
    bootstrapMessage.value = "数据库引导配置已保存，服务正在重启。";
    notify("数据库引导配置已保存，服务将重启");
    await waitForRestartAfterUpdate();
  } catch (error) {
    bootstrapError.value = bootstrapUpdateMessageFrom(error);
  } finally {
    bootstrapSaving.value = false;
  }
}

export function useAdminSettings() {
  return {
    settings,
    settingsLoading,
    settingsSaving,
    settingsError,
    settingsDraft,
    configurationVersion,
    runningConfigurationVersion,
    restartPending,
    bootstrapSettings,
    bootstrapLoading,
    bootstrapSaving,
    bootstrapTesting,
    bootstrapRestarting,
    bootstrapMessage,
    bootstrapError,
    bootstrapForm,
    changedSettings,
    settingGroups,
    getSettingsSection,
    getSettingsForSection,
    hasBootstrapForm,
    formatValue,
    loadSettings,
    saveSettings,
    discardSettings,
    loadBootstrap,
    bootstrapProviderList,
    testBootstrapSettings,
    saveBootstrapSettings,
  };
}
