<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { adminClient } from '../services/apiClient'
import {
  getErrorMessage,
  type BootstrapDatabasePayload,
  type BootstrapProvider,
  type BootstrapSettings,
} from '../services/adminApi'

const settings = ref<BootstrapSettings | null>(null)
const loading = ref(false)
const busy = ref(false)
const advanced = ref(true)
const inspection = ref('')

const form = reactive({
  provider: 'PostgreSQL',
  serverVersion: '15',
  host: '',
  port: 5432 as number | null,
  database: '',
  username: '',
  password: '',
  filePath: '',
  connectionString: '',
  masterKey: '',
  confirm: false,
})

const providers = computed(() => settings.value?.supportedProviders || [])
const selectedProvider = computed(() =>
  providers.value.find(provider => provider.provider === form.provider),
)
const isSqlite = computed(() => form.provider === 'SQLite')

function applyProvider(provider: BootstrapProvider) {
  form.provider = provider.provider
  form.serverVersion = provider.serverVersions[0] || ''
  form.port = provider.defaultPort
}

function providerChanged() {
  if (selectedProvider.value) applyProvider(selectedProvider.value)
}

function databasePayload(): BootstrapDatabasePayload {
  if (advanced.value) {
    return {
      provider: form.provider,
      serverVersion: form.serverVersion || null,
      connectionString: form.connectionString.trim(),
    }
  }

  return {
    provider: form.provider,
    serverVersion: form.serverVersion || null,
    host: form.host.trim(),
    port: form.port,
    database: form.database.trim(),
    username: form.username.trim(),
    password: form.password,
    filePath: form.filePath.trim(),
  }
}

function payload() {
  return {
    database: databasePayload(),
    masterKey: form.masterKey.trim() || null,
    confirm: form.confirm,
  }
}

async function load() {
  loading.value = true
  try {
    settings.value = await adminClient.getBootstrapSettings()
    form.provider = settings.value.provider
    form.serverVersion = settings.value.serverVersion || ''
  } catch (error) {
    ElMessage.error(`加载 bootstrap 配置失败: ${getErrorMessage(error)}`)
  } finally {
    loading.value = false
  }
}

async function testTarget() {
  busy.value = true
  inspection.value = ''
  try {
    const result = await adminClient.testBootstrapSettings(payload())
    inspection.value = result.hasProtectedData
      ? `${result.message} 主密钥兼容性：${result.masterKey}。`
      : result.message
  } catch (error) {
    ElMessage.error(`数据库测试失败: ${getErrorMessage(error)}`)
  } finally {
    busy.value = false
  }
}

async function save() {
  busy.value = true
  try {
    const result = await adminClient.updateBootstrapSettings(payload())
    form.password = ''
    form.masterKey = ''
    form.connectionString = ''
    ElMessage.success(result.message)
  } catch (error) {
    ElMessage.error(`保存 bootstrap 配置失败: ${getErrorMessage(error)}`)
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">本实例 Bootstrap 配置</div>
        <div class="page-sub">数据库密码和主密钥仅可写入，现有明文永不返回浏览器。</div>
      </div>
      <button class="btn btn-ghost" :disabled="loading || busy" @click="load">重新加载</button>
    </div>

    <div v-if="loading" class="empty">正在加载...</div>
    <template v-else-if="settings">
      <div class="alert alert-info">{{ settings.scopeNotice }}</div>
      <div class="hint" style="margin-top: 10px">
        当前目标：{{ settings.endpoint }} · 文件：{{ settings.filePath }} · 主密钥：已配置
        <template v-if="settings.singleInstanceOnly"> · SQLite 仅支持单实例</template>
      </div>

      <template v-if="settings.editable">
        <div class="field">
          <label>新数据库提供程序</label>
          <select v-model="form.provider" class="select" style="width: 100%" :disabled="busy" @change="providerChanged">
            <option v-for="provider in providers" :key="provider.provider" :value="provider.provider">
              {{ provider.provider }}{{ provider.singleInstanceOnly ? '（仅单实例）' : '' }}
            </option>
          </select>
        </div>

        <div v-if="!isSqlite" class="field">
          <label>服务器版本</label>
          <select v-if="selectedProvider?.serverVersions.length" v-model="form.serverVersion" class="select" style="width: 100%" :disabled="busy">
            <option v-for="version in selectedProvider.serverVersions" :key="version" :value="version">{{ version }}</option>
          </select>
          <input v-else v-model="form.serverVersion" class="input" :disabled="busy">
        </div>

        <div class="field">
          <label style="display: flex; gap: 8px; align-items: center">
            <input v-model="advanced" type="checkbox" :disabled="busy">
            使用完整连接字符串
          </label>
        </div>

        <div v-if="advanced" class="field">
          <label>替换连接字符串（完整、仅写）</label>
          <input v-model="form.connectionString" class="input" type="password" autocomplete="off" :disabled="busy">
        </div>
        <template v-else-if="isSqlite">
          <div class="field"><label>SQLite 文件</label><input v-model="form.filePath" class="input" :disabled="busy"></div>
        </template>
        <template v-else>
          <div class="field"><label>Host</label><input v-model="form.host" class="input" :disabled="busy"></div>
          <div class="field"><label>Port</label><input v-model.number="form.port" class="input" type="number" :disabled="busy"></div>
          <div class="field"><label>Database</label><input v-model="form.database" class="input" :disabled="busy"></div>
          <div class="field"><label>Username</label><input v-model="form.username" class="input" autocomplete="off" :disabled="busy"></div>
          <div class="field"><label>Password（仅写）</label><input v-model="form.password" class="input" type="password" autocomplete="new-password" :disabled="busy"></div>
        </template>

        <div class="field">
          <label>目标数据库已有数据时使用的主密钥（可选、仅写）</label>
          <input v-model="form.masterKey" class="input" type="password" autocomplete="off" :disabled="busy">
          <div class="hint">留空保留当前主密钥。普通编辑器不会执行主密钥轮换。</div>
        </div>

        <div v-if="inspection" class="alert alert-info">{{ inspection }}</div>

        <div class="field">
          <label style="display: flex; gap: 8px; align-items: center">
            <input v-model="form.confirm" type="checkbox" :disabled="busy">
            我确认这只修改处理本请求的实例，并会停止该实例以等待受控重启
          </label>
        </div>

        <div style="display: flex; gap: 8px">
          <button class="btn btn-ghost" :disabled="busy" @click="testTarget">测试并分类目标</button>
          <button class="btn" :disabled="busy || !form.confirm" @click="save">保存并重启本实例</button>
        </div>
      </template>
    </template>
  </div>
</template>
