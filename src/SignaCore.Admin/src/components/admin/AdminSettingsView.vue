<script setup lang="ts">
import { useAdminSettings } from "../../composables/admin/useAdminSettings";

const {
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
  hasBootstrapForm,
  formatValue,
  loadSettings,
  saveSettings,
  discardSettings,
  testBootstrapSettings,
  saveBootstrapSettings,
} = useAdminSettings();
</script>

<template>
  <section class="console-view">
    <div class="console-page-heading">
      <div>
        <p class="console-eyebrow">SYSTEM CONFIGURATION</p>
        <h1>运行配置</h1>
        <p>配置值按后端允许的键提交；Secret 从不回显，空白代表保持不变。</p>
      </div>
      <div class="heading-actions">
        <button
          class="console-button secondary"
          :disabled="!changedSettings.length || settingsSaving"
          @click="discardSettings"
        >
          撤销修改</button
        ><button
          class="console-button primary"
          :disabled="!changedSettings.length || settingsSaving"
          @click="saveSettings"
        >
          {{
            settingsSaving ? "保存中…" : `保存 ${changedSettings.length || ""}`
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
          }}。所有配置变更都需要服务重启后生效。
        </p>
      </div>
    </div>
    <article class="console-panel version-panel">
      <div>
        <span class="console-eyebrow">CONFIGURATION VERSION</span
        ><strong>v{{ configurationVersion }}</strong>
      </div>
      <div>
        <span>运行中</span><b>v{{ runningConfigurationVersion }}</b>
      </div>
      <div>
        <span>变更项</span><b>{{ changedSettings.length }}</b>
      </div>
    </article>
    <div v-if="settingsLoading" class="console-panel console-table-state">
      <span class="console-spinner"></span>读取运行配置…
    </div>
    <div
      v-else-if="settingsError"
      class="console-panel console-table-state error"
    >
      {{ settingsError }}
      <button class="text-button" @click="loadSettings">重试</button>
    </div>
    <div v-else class="settings-groups">
      <article
        v-for="group in settingGroups"
        :key="group.name"
        class="console-panel settings-group"
      >
        <div class="panel-heading">
          <div>
            <p class="console-eyebrow">{{ group.name.toUpperCase() }}</p>
            <h2>{{ group.name }}</h2>
          </div>
          <span class="panel-note">{{ group.items.length }} 项</span>
        </div>
        <div class="settings-list">
          <label
            v-for="setting in group.items"
            :key="setting.key"
            class="setting-row"
            ><span
              ><b>{{ setting.key }}</b
              ><small>{{
                setting.isSecret
                  ? "Secret：不会回显，留空保持当前值"
                  : `类型：${setting.valueType} · 当前：${formatValue(setting)}`
              }}</small></span
            ><input
              v-model="settingsDraft[setting.key]"
              class="console-input"
              :type="setting.isSecret ? 'password' : 'text'"
              :placeholder="setting.isSecret ? '留空表示不变' : '输入配置值'"
          /></label>
        </div>
      </article>
    </div>
    <article class="console-panel bootstrap-panel">
      <div class="panel-heading">
        <div>
          <p class="console-eyebrow">BOOTSTRAP TARGET</p>
          <h2>数据库引导配置</h2>
          <p>后端支持读取当前目标、测试候选连接并保存后重启当前实例。</p>
        </div>
        <span class="status-pill" :class="hasBootstrapForm ? 'green' : 'amber'"
          ><i></i
          >{{
            bootstrapLoading
              ? "读取中"
              : hasBootstrapForm
                ? "可编辑"
                : "不可编辑"
          }}</span
        >
      </div>
      <div v-if="bootstrapError" class="inline-error">{{ bootstrapError }}</div>
      <div v-if="bootstrapMessage" class="console-info-band compact-band">
        <span>✓</span>
        <p>{{ bootstrapMessage }}</p>
      </div>
      <div v-if="bootstrapSettings" class="bootstrap-grid">
        <label
          >Provider<input
            v-model="bootstrapForm.provider"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >Server version<input
            v-model="bootstrapForm.serverVersion"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label class="wide-field"
          >当前 endpoint<input
            v-model="bootstrapForm.endpoint"
            class="console-input mono"
            disabled /></label
        ><label
          >SQLite 文件路径<input
            v-model="bootstrapForm.filePath"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >Host<input
            v-model="bootstrapForm.host"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >Port<input
            v-model="bootstrapForm.port"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >Database<input
            v-model="bootstrapForm.database"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >Username<input
            v-model="bootstrapForm.username"
            class="console-input"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >Password（只写）<input
            v-model="bootstrapForm.password"
            class="console-input"
            type="password"
            :disabled="!hasBootstrapForm" /></label
        ><label class="wide-field"
          >高级连接字符串（只写）<input
            v-model="bootstrapForm.connectionString"
            class="console-input"
            type="password"
            :disabled="!hasBootstrapForm" /></label
        ><label
          >目标 Master Key（只写）<input
            v-model="bootstrapForm.masterKey"
            class="console-input"
            type="password"
            :disabled="!hasBootstrapForm"
        /></label>
      </div>
      <div v-if="bootstrapSettings" class="bootstrap-actions">
        <label class="confirm-line"
          ><input
            v-model="bootstrapForm.confirm"
            type="checkbox"
            :disabled="!hasBootstrapForm"
          />我确认数据库切换会修改引导文件并重启当前服务</label
        >
        <div>
          <button
            class="console-button secondary"
            :disabled="!hasBootstrapForm || bootstrapTesting || bootstrapSaving"
            @click="testBootstrapSettings"
          >
            {{ bootstrapTesting ? "测试中…" : "测试连接" }}</button
          ><button
            class="console-button danger"
            :disabled="!hasBootstrapForm || bootstrapTesting || bootstrapSaving"
            @click="saveBootstrapSettings"
          >
            {{ bootstrapSaving ? "保存中…" : "保存并重启" }}
          </button>
        </div>
      </div>
    </article>
  </section>
</template>
