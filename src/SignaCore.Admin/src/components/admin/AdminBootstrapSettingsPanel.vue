<script setup lang="ts">
import { useAdminSettings } from "../../composables/admin/useAdminSettings";

const {
  bootstrapSettings,
  bootstrapLoading,
  bootstrapSaving,
  bootstrapTesting,
  bootstrapMessage,
  bootstrapError,
  bootstrapForm,
  hasBootstrapForm,
  testBootstrapSettings,
  saveBootstrapSettings,
} = useAdminSettings();
</script>

<template>
  <article class="console-panel bootstrap-panel">
    <div class="panel-heading">
      <div>
        <h2>当前实例数据库目标</h2>
        <p>
          这项设置只修改当前实例的引导文件，不会自动分发到其他实例；保存后会重启服务。
        </p>
      </div>
      <span class="status-pill" :class="hasBootstrapForm ? 'green' : 'amber'">
        <i></i>{{
          bootstrapLoading ? "读取中" : hasBootstrapForm ? "可编辑" : "不可编辑"
        }}
      </span>
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
    <div v-else-if="!bootstrapLoading" class="console-table-state">
      暂无可编辑的数据库引导配置。
    </div>
  </article>
</template>
