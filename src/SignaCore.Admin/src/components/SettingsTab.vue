<script setup lang="ts">
import {
  useSettings,
  editedValue,
  setEditedValue,
  saveSettings,
  discardChanges,
  loadSettings,
} from '../composables/useSettings'
import type { AdminSetting } from '../services/adminApi'
import { formatDate } from '../utils/format'
import { I } from '../utils/icons'
import BootstrapSettingsCard from './BootstrapSettingsCard.vue'

const {
  groups,
  loading,
  saving,
  hasChanges,
  configurationVersion,
  runningConfigurationVersion,
  restartPending,
} = useSettings()

/* 分组标题：配置键前缀 -> 中文说明 */
const groupLabels: Record<string, string> = {
  Endpoints: '对外地址',
  Jwt: '令牌签发',
  RefreshToken: '刷新令牌',
  PasswordHasher: '密码哈希',
  Security: '安全开关',
  Admin: '管理员',
  AdminWeb: '管理控制台',
  Callback: '回调策略',
  ReverseProxy: '反向代理',
  Sms: '短信',
  WeChat: '微信',
  Ldap: 'LDAP',
  Loki: '日志导出',
  OpenTelemetry: '链路追踪',
  Consul: '服务发现',
}

function onInput(setting: AdminSetting, event: Event) {
  setEditedValue(setting, (event.target as HTMLInputElement | HTMLSelectElement).value)
}

function placeholderFor(setting: AdminSetting) {
  if (setting.isSecret) {
    return setting.hasValue ? '已设置，留空表示不修改' : '未设置'
  }
  return setting.valueType === 'Json' ? '合法 JSON' : ''
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <div class="page-title">全局配置</div>
        <div class="page-sub">
          配置存储在业务数据库中，所有实例读取同一份快照。已保存版本 v{{ configurationVersion }}，
          本实例运行版本 v{{ runningConfigurationVersion }}。
        </div>
      </div>
      <div style="display: flex; gap: 8px">
        <button class="btn btn-ghost" :disabled="loading || saving" @click="loadSettings">重新加载</button>
        <button class="btn btn-ghost" :disabled="!hasChanges || saving" @click="discardChanges">放弃修改</button>
        <button class="btn" :disabled="!hasChanges || saving" @click="saveSettings">
          <svg v-if="saving" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          {{ saving ? '保存中...' : '保存' }}
        </button>
      </div>
    </div>

    <div v-if="restartPending" class="alert alert-info section-gap">
      <div class="alert-ico-box">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
      </div>
      <div>
        配置已保存但尚未生效。请重启所有 SignaCore 实例；多实例部署请执行滚动重启。
      </div>
    </div>

    <BootstrapSettingsCard />

    <div v-if="loading" class="empty">正在加载配置...</div>

    <div v-for="group in groups" v-else :key="group.prefix" class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ groupLabels[group.prefix] || group.prefix }}</div>
        </div>
      </div>

      <div v-for="setting in group.items" :key="setting.key" class="field">
        <label>{{ setting.key }}<template v-if="setting.isSecret"> · 机密</template></label>

        <select
          v-if="setting.valueType === 'Boolean'"
          class="select"
          style="width: 100%"
          :value="editedValue(setting)"
          :disabled="saving"
          @change="onInput(setting, $event)"
        >
          <option value="true">true</option>
          <option value="false">false</option>
        </select>

        <input
          v-else
          class="input"
          style="width: 100%"
          :type="setting.isSecret ? 'password' : 'text'"
          :value="editedValue(setting)"
          :placeholder="placeholderFor(setting)"
          :disabled="saving"
          autocomplete="off"
          @input="onInput(setting, $event)"
        >

        <div class="hint">
          {{ setting.valueType }}
          <template v-if="setting.updatedAt">
            · 最后修改 {{ formatDate(setting.updatedAt) }}
            <template v-if="setting.updatedBy"> by {{ setting.updatedBy }}</template>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
