import { computed, reactive, ref } from "vue";
import { adminClient } from "../../services/apiClient";
import {
  getErrorMessage,
  type AdminSetting,
  type BootstrapSettings,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
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
  prefixes?: string[];
};

export const adminSettingsSections: AdminSettingsSection[] = [
  {
    key: "settings-identity",
    label: "域名与令牌",
    description: "配置公开地址、JWT、刷新令牌及密码哈希策略。",
    prefixes: ["Endpoints", "Jwt", "RefreshToken", "PasswordHasher", "Security"],
  },
  {
    key: "settings-admin",
    label: "管理端",
    description: "配置管理端允许的来源和初始管理员标识。",
    prefixes: ["Admin", "AdminWeb"],
  },
  {
    key: "settings-network",
    label: "回调与代理",
    description: "配置回调地址边界和反向代理可信来源。",
    prefixes: ["Callback", "ReverseProxy"],
  },
  {
    key: "settings-sms",
    label: "短信登录",
    description: "配置短信验证码限制、绕过规则和短信服务档案。",
    prefixes: ["Sms"],
  },
  {
    key: "settings-wechat",
    label: "微信登录",
    description: "配置微信应用标识、密钥和接口地址。",
    prefixes: ["WeChat"],
  },
  {
    key: "settings-ldap",
    label: "LDAP 目录",
    description: "配置 LDAP 开关、默认目录和目录连接信息。",
    prefixes: ["Ldap"],
  },
  {
    key: "settings-observability",
    label: "日志与监控",
    description: "配置 Loki 和 OpenTelemetry 的上报地址。",
    prefixes: ["Loki", "OpenTelemetry"],
  },
  {
    key: "settings-consul",
    label: "服务发现",
    description: "配置 Consul 连接和服务注册发现行为。",
    prefixes: ["Consul"],
  },
  {
    key: "settings-bootstrap",
    label: "数据库引导",
    description: "切换当前实例的引导数据库目标；操作会重启服务。",
  },
];

const settings = ref<AdminSetting[]>([]);
const settingsLoading = ref(false);
const settingsSaving = ref(false);
const settingsError = ref("");
const settingsDraft = reactive<Record<string, string>>({});
const configurationVersion = ref(0);
const runningConfigurationVersion = ref(0);
const restartPending = ref(false);
const bootstrapSettings = ref<BootstrapSettings | null>(null);
const bootstrapLoading = ref(false);
const bootstrapSaving = ref(false);
const bootstrapTesting = ref(false);
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
    return setting.isSecret
      ? value.trim().length > 0
      : value !== (setting.value ?? "");
  }),
);
const settingGroups = computed(() => {
  const map = new Map<string, AdminSetting[]>();
  for (const setting of settings.value) {
    const prefix = setting.key.split(":")[0] || "其他";
    map.set(prefix, [...(map.get(prefix) ?? []), setting]);
  }
  return [...map.entries()].map(([name, items]) => ({ name, items }));
});
const hasBootstrapForm = computed(() =>
  Boolean(bootstrapSettings.value?.editable),
);

function getSettingsSection(key: SettingsSectionKey) {
  return adminSettingsSections.find((section) => section.key === key)!;
}

function getSettingsForSection(key: SettingsSectionKey) {
  const section = getSettingsSection(key);
  if (!section.prefixes) return [];
  return settings.value.filter((setting) => {
    const prefix = setting.key.split(":")[0];
    return section.prefixes?.includes(prefix) ?? false;
  });
}

function formatValue(setting: AdminSetting) {
  if (setting.isSecret)
    return setting.hasValue ? "已配置（不会回显）" : "未配置";
  if (setting.valueType === "Boolean")
    return setting.value === "true" ? "启用" : "停用";
  return setting.value || "空";
}

async function loadSettings() {
  settingsLoading.value = true;
  settingsError.value = "";
  try {
    const result = await adminClient.getSettings();
    settings.value = result.items;
    configurationVersion.value = result.configurationVersion;
    runningConfigurationVersion.value = result.runningConfigurationVersion;
    restartPending.value = result.restartPending;
    for (const key of Object.keys(settingsDraft)) delete settingsDraft[key];
    for (const setting of result.items)
      if (!setting.isSecret) settingsDraft[setting.key] = setting.value ?? "";
  } catch (error) {
    settingsError.value = getErrorMessage(error);
    handleApiError("加载运行配置失败", error);
  } finally {
    settingsLoading.value = false;
  }
}

async function saveSettings(keys?: string[]) {
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
    const values: Record<string, string> = {};
    for (const setting of pending)
      values[setting.key] = settingsDraft[setting.key] ?? "";
    const result = await adminClient.updateSettings(values);
    restartPending.value = result.restartRequired;
    notify(result.message);
    await loadSettings();
    const availableKeys = new Set(settings.value.map((setting) => setting.key));
    for (const [key, value] of draftsToPreserve)
      if (availableKeys.has(key)) settingsDraft[key] = value;
  } catch (error) {
    handleApiError("保存运行配置失败", error);
  } finally {
    settingsSaving.value = false;
  }
}

function discardSettings(keys?: string[]) {
  const keySet = keys ? new Set(keys) : null;
  for (const setting of settings.value) {
    if (keySet && !keySet.has(setting.key)) continue;
    settingsDraft[setting.key] = setting.isSecret ? "" : (setting.value ?? "");
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

function bootstrapPayload() {
  return {
    database: {
      provider: bootstrapForm.provider,
      serverVersion: bootstrapForm.serverVersion || null,
      host: bootstrapForm.host.trim() || undefined,
      port: bootstrapForm.port ? Number(bootstrapForm.port) : null,
      database: bootstrapForm.database.trim() || undefined,
      username: bootstrapForm.username.trim() || undefined,
      password: bootstrapForm.password || undefined,
      filePath: bootstrapForm.filePath.trim() || undefined,
      connectionString: bootstrapForm.connectionString.trim() || undefined,
    },
    masterKey: bootstrapForm.masterKey.trim() || null,
    confirm: bootstrapForm.confirm,
  };
}

async function testBootstrapSettings() {
  if (!bootstrapForm.confirm)
    return notify("测试前请确认你理解数据库目标切换影响");
  bootstrapTesting.value = true;
  bootstrapError.value = "";
  try {
    const result = await adminClient.testBootstrapSettings(bootstrapPayload());
    bootstrapMessage.value = `${result.message} 目标：${result.endpoint}`;
  } catch (error) {
    bootstrapError.value = getErrorMessage(error);
  } finally {
    bootstrapTesting.value = false;
  }
}

async function saveBootstrapSettings() {
  if (!bootstrapForm.confirm) return notify("保存前必须明确确认，服务会重启");
  bootstrapSaving.value = true;
  bootstrapError.value = "";
  try {
    const result =
      await adminClient.updateBootstrapSettings(bootstrapPayload());
    bootstrapMessage.value = result.message;
    notify("数据库引导配置已保存，服务将重启");
  } catch (error) {
    bootstrapError.value = getErrorMessage(error);
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
    testBootstrapSettings,
    saveBootstrapSettings,
  };
}
