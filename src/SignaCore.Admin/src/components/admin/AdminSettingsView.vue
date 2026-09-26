<script setup lang="ts">
import { computed } from "vue";
import AdminBootstrapSettingsPanel from "./AdminBootstrapSettingsPanel.vue";
import {
  useAdminSettings,
  type SettingsSectionKey,
} from "../../composables/admin/useAdminSettings";
import type { AdminSettingValue } from "../../services/adminApi";

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
  "endpoints.public_base_url": "公开基础地址",
  "jwt.issuer": "令牌签发者",
  "jwt.audience": "令牌受众",
  "jwt.token_expiration_hours": "访问令牌有效期（小时）",
  "refresh_token.expiration_days": "刷新令牌有效期（天）",
  "password_hasher.work_factor": "密码哈希工作因子",
  "security.allow_non_https_issuer": "允许非 HTTPS 签发地址",
  "admin_web.allowed_origins": "管理端允许来源",
  "admin.username": "管理员标识",
  "callback.allowed_domains": "回调允许域名",
  "callback.allow_private_addresses": "允许回调到私有地址",
  "callback.require_https": "回调必须使用 HTTPS",
  "reverse_proxy.known_proxies": "可信反向代理",
  "sms.otp_ttl_seconds": "验证码有效期（秒）",
  "sms.max_attempts": "最大验证次数",
  "sms.lockout_seconds": "锁定时长（秒）",
  "sms.min_send_interval_seconds": "最小发送间隔（秒）",
  "sms.max_sends_per_hour": "每小时最大发送数",
  "sms.max_sends_per_day": "每天最大发送数",
  "sms.otp_hmac_key": "验证码签名密钥",
  "sms.bypass_code": "绕过验证码",
  "sms.bypass_phones": "绕过手机号",
  "sms.profiles": "短信服务档案",
  "wechat.app_id": "微信应用 ID",
  "wechat.app_secret": "微信应用密钥",
  "wechat.api_base_url": "微信接口地址",
  "ldap.enabled": "启用 LDAP",
  "ldap.default_directory_key": "默认目录标识",
  "ldap.max_concurrent_operations": "最大并发操作数",
  "ldap.directories": "LDAP 目录",
  "loki.uri": "Loki 地址（HTTPS）",
  "loki.authorization": "Loki 授权头",
  "opentelemetry.otlp_endpoint": "OpenTelemetry 地址",
  "consul.host": "Consul 主机",
  "consul.port": "Consul 端口",
  "consul.token": "Consul 令牌",
  "consul.discovery.enabled": "启用服务发现",
  "consul.discovery.register": "注册当前服务",
  "consul.discovery.deregister": "停止时注销服务",
  "consul.discovery.service_name": "服务名称",
  "consul.discovery.health_check_path": "健康检查路径",
  "consul.discovery.prefer_ip_address": "优先使用 IP 地址",
  "consul.discovery.ip_address": "注册 IP 地址",
  "consul.discovery.port": "注册端口",
};

function settingLabel(setting: AdminSettingValue) {
  return settingLabels[setting.key] ?? setting.key;
}

function settingHint(setting: AdminSettingValue) {
  if (setting.isSensitive)
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
      v-else-if="!isBootstrap && runningConfigurationVersion === null"
      class="console-warning-banner"
    >
      <span>!</span>
      <div>
        <b>运行版本未知</b>
        <p>
          本实例没有返回有效的运行版本信息；保存的配置是否已生效无法判断，请以实例状态为准。
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
              v-if="setting.valueType === 'boolean' && !setting.isSensitive"
              v-model="settingsDraft[setting.key]"
              class="console-input"
            >
              <option value="true">启用</option>
              <option value="false">停用</option>
            </select>
            <textarea
              v-else-if="setting.valueType === 'json'"
              v-model="settingsDraft[setting.key]"
              class="console-input settings-json-input"
              rows="2"
              :placeholder="setting.isSensitive ? '留空表示不变' : '输入 JSON 配置值'"
            ></textarea>
            <input
              v-else
              v-model="settingsDraft[setting.key]"
              class="console-input"
              :type="
                setting.isSensitive
                  ? 'password'
                  : setting.valueType === 'number'
                    ? 'number'
                    : 'text'
              "
              :placeholder="setting.isSensitive ? '留空表示不变' : '输入配置值'"
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
