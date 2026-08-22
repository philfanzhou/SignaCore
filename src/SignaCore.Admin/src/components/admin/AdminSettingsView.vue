<script setup lang="ts">
import { computed } from "vue";
import AdminBootstrapSettingsPanel from "./AdminBootstrapSettingsPanel.vue";
import {
  useAdminSettings,
  type SettingsSectionKey,
} from "../../composables/admin/useAdminSettings";
import type { AdminSetting } from "../../services/adminApi";

const props = defineProps<{
  section: SettingsSectionKey;
}>();

const {
  settingsLoading,
  settingsSaving,
  settingsError,
  settingsDraft,
  configurationVersion,
  runningConfigurationVersion,
  restartPending,
  changedSettings,
  formatValue,
  getSettingsSection,
  getSettingsForSection,
  loadSettings,
  saveSettings,
  discardSettings,
} = useAdminSettings();

const sectionInfo = computed(() => getSettingsSection(props.section));
const sectionItems = computed(() => getSettingsForSection(props.section));
const sectionChangedItems = computed(() => {
  const keys = new Set(sectionItems.value.map((setting) => setting.key));
  return changedSettings.value.filter((setting) => keys.has(setting.key));
});
const isBootstrap = computed(() => props.section === "settings-bootstrap");

const settingLabels: Record<string, string> = {
  "Endpoints:PublicBaseUrl": "公开基础地址",
  "Jwt:Issuer": "令牌签发者",
  "Jwt:Audience": "令牌受众",
  "Jwt:TokenExpirationHours": "访问令牌有效期（小时）",
  "RefreshToken:ExpirationDays": "刷新令牌有效期（天）",
  "PasswordHasher:WorkFactor": "密码哈希工作因子",
  "Security:AllowNonHttpsIssuer": "允许非 HTTPS 签发地址",
  "AdminWeb:AllowedOrigins": "管理端允许来源",
  "Admin:Username": "管理员标识",
  "Callback:AllowedDomains": "回调允许域名",
  "Callback:AllowPrivateAddresses": "允许回调到私有地址",
  "Callback:RequireHttps": "回调必须使用 HTTPS",
  "ReverseProxy:KnownProxies": "可信反向代理",
  "Sms:OtpTtlSeconds": "验证码有效期（秒）",
  "Sms:MaxAttempts": "最大验证次数",
  "Sms:LockoutSeconds": "锁定时长（秒）",
  "Sms:MinSendIntervalSeconds": "最小发送间隔（秒）",
  "Sms:MaxSendsPerHour": "每小时最大发送数",
  "Sms:MaxSendsPerDay": "每天最大发送数",
  "Sms:OtpHmacKey": "验证码签名密钥",
  "Sms:BypassCode": "绕过验证码",
  "Sms:BypassPhones": "绕过手机号",
  "Sms:Profiles": "短信服务档案",
  "WeChat:AppId": "微信应用 ID",
  "WeChat:AppSecret": "微信应用密钥",
  "WeChat:ApiBaseUrl": "微信接口地址",
  "Ldap:Enabled": "启用 LDAP",
  "Ldap:DefaultDirectoryKey": "默认目录标识",
  "Ldap:MaxConcurrentOperations": "最大并发操作数",
  "Ldap:Directories": "LDAP 目录",
  "Loki:Uri": "Loki 地址",
  "OpenTelemetry:OtlpEndpoint": "OpenTelemetry 地址",
  "Consul:Host": "Consul 主机",
  "Consul:Port": "Consul 端口",
  "Consul:Token": "Consul 令牌",
  "Consul:Discovery:Enabled": "启用服务发现",
  "Consul:Discovery:Register": "注册当前服务",
  "Consul:Discovery:Deregister": "停止时注销服务",
  "Consul:Discovery:ServiceName": "服务名称",
  "Consul:Discovery:HealthCheckPath": "健康检查路径",
  "Consul:Discovery:PreferIPAddress": "优先使用 IP 地址",
  "Consul:Discovery:IPAddress": "注册 IP 地址",
  "Consul:Discovery:Port": "注册端口",
};

function settingLabel(setting: AdminSetting) {
  return settingLabels[setting.key] ?? setting.key;
}

function settingHint(setting: AdminSetting) {
  if (setting.isSecret)
    return setting.hasValue ? "已配置；不会回显，留空保持当前值" : "未配置；不会回显";
  return `键 ${setting.key} · ${setting.valueType} · 当前：${formatValue(setting)}`;
}

function saveCurrentSection() {
  void saveSettings(sectionItems.value.map((setting) => setting.key));
}

function discardCurrentSection() {
  discardSettings(sectionItems.value.map((setting) => setting.key));
}
</script>

<template>
  <section class="console-view settings-view">
    <div class="console-page-heading">
      <div>
        <h1>{{ sectionInfo.label }}</h1>
        <p>{{ sectionInfo.description }}</p>
      </div>
      <div v-if="!isBootstrap" class="heading-actions">
        <button
          class="console-button secondary"
          :disabled="!sectionChangedItems.length || settingsSaving"
          @click="discardCurrentSection"
        >
          撤销修改</button
        ><button
          class="console-button primary"
          :disabled="!sectionChangedItems.length || settingsSaving"
          @click="saveCurrentSection"
        >
          {{
            settingsSaving
              ? "保存中…"
              : `保存 ${sectionChangedItems.length || ""}`
          }}
        </button>
      </div>
    </div>

    <div v-if="restartPending" class="console-warning-banner">
      <span>!</span>
      <div>
        <b>有配置等待重启</b>
        <p>
          配置版本 v{{ configurationVersion }} 已保存，当前运行版本为 v{{
            runningConfigurationVersion
          }}；所有运行配置变更都需要服务重启后生效。
        </p>
      </div>
    </div>

    <div
      v-if="!isBootstrap && settingsLoading"
      class="console-panel console-table-state"
    >
      <span class="console-spinner"></span>读取运行配置…
    </div>
    <div
      v-else-if="!isBootstrap && settingsError"
      class="console-panel console-table-state error"
    >
      {{ settingsError }}
      <button class="text-button" @click="loadSettings">重试</button>
    </div>
    <template v-else>
      <AdminBootstrapSettingsPanel v-if="isBootstrap" />

      <article v-else class="console-panel settings-single-panel">
        <div class="panel-heading">
          <div>
            <h2>{{ sectionInfo.label }}</h2>
            <p>只显示这一配置域的键；提交时只会发送当前分组的变更。</p>
          </div>
          <span class="panel-note"
            >{{ sectionItems.length }} 项 · 未保存
            {{ sectionChangedItems.length }} 项</span
          >
        </div>
        <div v-if="sectionItems.length" class="settings-list">
          <label
            v-for="setting in sectionItems"
            :key="setting.key"
            class="setting-row"
          >
            <span>
              <b>{{ settingLabel(setting) }}</b>
              <small>{{ settingHint(setting) }}</small>
            </span>
            <select
              v-if="setting.valueType === 'Boolean' && !setting.isSecret"
              v-model="settingsDraft[setting.key]"
              class="console-input"
            >
              <option value="true">启用</option>
              <option value="false">停用</option>
            </select>
            <textarea
              v-else-if="setting.valueType === 'Json'"
              v-model="settingsDraft[setting.key]"
              class="console-input settings-json-input"
              rows="2"
              :placeholder="setting.isSecret ? '留空表示不变' : '输入 JSON 配置值'"
            ></textarea>
            <input
              v-else
              v-model="settingsDraft[setting.key]"
              class="console-input"
              :type="
                setting.isSecret
                  ? 'password'
                  : setting.valueType === 'Number'
                    ? 'number'
                    : 'text'
              "
              :placeholder="setting.isSecret ? '留空表示不变' : '输入配置值'"
            />
          </label>
        </div>
        <div v-else class="console-table-state settings-section-state">
          当前服务没有返回这一配置域的可管理项。
        </div>
      </article>
    </template>
  </section>
</template>
