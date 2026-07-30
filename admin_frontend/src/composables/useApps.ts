import { computed, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { type AdminApp } from '../services/adminApi'
import { adminClient } from '../services/apiClient'
import { normalizeTtlValue } from '../utils/format'
import { handleApiError } from './useSession'
import { registerSessionHooks } from './sessionHooks'

const loadingApps = ref(false)
const creatingApp = ref(false)
const savingCallback = ref(false)
const resettingSecret = ref(false)
const deletingApp = ref(false)
const apps = ref<AdminApp[]>([])
const latestCreatedAppSecret = ref('')
const latestSecretAppId = ref('')
const showSecretDialog = ref(false)
const secretCopied = ref(false)
let secretCopiedTimer: number | undefined

const showCreateAppDialog = ref(false)

const activeAppsCount = computed(() => apps.value.filter((a) => a.isActive).length)
const disabledAppsCount = computed(() => apps.value.filter((a) => !a.isActive).length)

const createAppForm = reactive({
  appName: '',
  callbackUrl: '',
  ttlSeconds: 2,
  ttlUnit: 'h' as 'h' | 'd',
  neverExpire: false,
})

const callbackForm = reactive({
  appId: '',
  callbackUrl: '',
  ttlSeconds: 2,
  ttlUnit: 'h' as 'h' | 'd',
  neverExpire: false,
  isActive: true,
})

const selectedApp = computed(() => apps.value.find((item) => item.appId === callbackForm.appId) ?? null)

/* ============ 抽屉与模态框状态（展示层新增，不调用 API） ============ */
/* visible 控制挂载、open 控制 .open 类，拆分以驱动进出场过渡（对齐样稿 double-rAF 模式） */
const appDrawerVisible = ref(false)
const appDrawerOpen = ref(false)
const appDrawerApp = ref<AdminApp | null>(null)
let appDrawerTimer: number | undefined

const deleteAppOpen = ref(false)
const deleteAppTarget = ref<AdminApp | null>(null)
const deleteAppConfirmId = ref('')

const secretSavedConfirmed = ref(false)

function resetCreateAppForm() {
  createAppForm.appName = ''
  createAppForm.callbackUrl = ''
  createAppForm.ttlSeconds = 2
  createAppForm.ttlUnit = 'h'
  createAppForm.neverExpire = false
}

function openCreateAppDialog() {
  resetCreateAppForm()
  showCreateAppDialog.value = true
}

async function loadApps() {
  loadingApps.value = true
  try {
    apps.value = await adminClient.getApps()
    // keep the open app drawer in sync with the refreshed list
    const drawerApp = appDrawerApp.value
    if (drawerApp) {
      const fresh = apps.value.find((item) => item.appId === drawerApp.appId)
      if (fresh) appDrawerApp.value = fresh
    }
  } catch (error) {
    handleApiError('加载应用列表失败', error)
  } finally {
    loadingApps.value = false
  }
}

async function handleCreateApp() {
  if (!createAppForm.appName) {
    ElMessage.warning('请输入应用名称')
    return
  }

  creatingApp.value = true
  try {
    const ttlSeconds = createAppForm.neverExpire
      ? -1
      : createAppForm.ttlUnit === 'd'
        ? normalizeTtlValue(createAppForm.ttlSeconds) * 86400
        : normalizeTtlValue(createAppForm.ttlSeconds) * 3600
    const result = await adminClient.createApp({
      appName: createAppForm.appName,
      callbackUrl: createAppForm.callbackUrl || undefined,
      ttlSeconds,
    })
    ElMessage.success('应用创建成功')
    showCreateAppDialog.value = false
    resetCreateAppForm()
    latestCreatedAppSecret.value = result.appSecret
    latestSecretAppId.value = result.appId
    secretSavedConfirmed.value = false
    secretCopied.value = false
    showSecretDialog.value = true
    await loadApps()
  } catch (error) {
    handleApiError('创建应用失败', error)
  } finally {
    creatingApp.value = false
  }
}

async function handleResetSecret(app: AdminApp) {
  try {
    await ElMessageBox.confirm(
      `确定要重置应用 "${app.appName}" (${app.appId}) 的 Secret 吗？当前 Secret 将立即失效。`,
      '重置应用密钥',
      { confirmButtonText: '重置', cancelButtonText: '取消', type: 'warning' }
    )
  } catch {
    return
  }

  resettingSecret.value = true
  try {
    const result = await adminClient.resetAppSecret(app.appId)
    latestCreatedAppSecret.value = result.appSecret
    latestSecretAppId.value = app.appId
    secretSavedConfirmed.value = false
    secretCopied.value = false
    showSecretDialog.value = true
    ElMessage.success('Secret 重置成功')
    await loadApps()
  } catch (error) {
    handleApiError('重置 Secret 失败', error)
  } finally {
    resettingSecret.value = false
  }
}

async function handleDeleteApp(app: AdminApp) {
  deletingApp.value = true
  try {
    await adminClient.deleteApp(app.appId)
    ElMessage.success('应用已删除')
    deleteAppOpen.value = false
    closeAppDrawer()
    deleteAppTarget.value = null
    deleteAppConfirmId.value = ''
    if (callbackForm.appId === app.appId) {
      callbackForm.appId = ''
      callbackForm.callbackUrl = ''
      callbackForm.ttlSeconds = 2
      callbackForm.ttlUnit = 'h'
      callbackForm.neverExpire = false
      callbackForm.isActive = true
    }
    await loadApps()
  } catch (error) {
    handleApiError('删除应用失败', error)
  } finally {
    deletingApp.value = false
  }
}

function fillCallbackForm(app: AdminApp) {
  callbackForm.appId = app.appId
  callbackForm.callbackUrl = app.callbackUrl || ''
  if (!app.callbackExpiresAt) {
    callbackForm.neverExpire = !!app.callbackUrl
    callbackForm.ttlSeconds = 2
    callbackForm.ttlUnit = 'h'
  } else {
    callbackForm.neverExpire = false
    const remainingSec = Math.max(1, Math.floor(app.callbackExpiresAt - Date.now() / 1000))
    if (remainingSec >= 86400 && remainingSec % 86400 === 0) {
      callbackForm.ttlUnit = 'd'
      callbackForm.ttlSeconds = remainingSec / 86400
    } else {
      callbackForm.ttlUnit = 'h'
      callbackForm.ttlSeconds = Math.max(1, Math.ceil(remainingSec / 3600))
    }
  }
  callbackForm.isActive = app.isActive
}

function onAppSelected() {
  if (!callbackForm.appId) return
  const app = apps.value.find(a => a.appId === callbackForm.appId)
  if (app) {
    fillCallbackForm(app)
  }
}

async function handleSaveCallback(): Promise<boolean> {
  if (!callbackForm.appId) {
    ElMessage.warning('请选择一个应用')
    return false
  }

  savingCallback.value = true
  try {
    const ttlSeconds = callbackForm.neverExpire
      ? -1
      : callbackForm.ttlUnit === 'd'
        ? normalizeTtlValue(callbackForm.ttlSeconds) * 86400
        : normalizeTtlValue(callbackForm.ttlSeconds) * 3600
    await adminClient.updateCallback(callbackForm.appId, {
      callbackUrl: callbackForm.callbackUrl || undefined,
      ttlSeconds,
      isActive: callbackForm.isActive,
    })
    ElMessage.success('回调配置保存成功')
    await loadApps()
    return true
  } catch (error) {
    handleApiError('保存回调配置失败', error)
    return false
  } finally {
    savingCallback.value = false
  }
}

/* 应用 drawer"保存配置"：成功后按样稿行为关闭 drawer（回调管理 Tab 仍用 handleSaveCallback，不关闭） */
async function saveCallbackFromDrawer() {
  const ok = await handleSaveCallback()
  if (ok) closeAppDrawer()
}

function markSecretCopied() {
  secretCopied.value = true
  if (secretCopiedTimer) window.clearTimeout(secretCopiedTimer)
  secretCopiedTimer = window.setTimeout(() => {
    secretCopied.value = false
    secretCopiedTimer = undefined
  }, 1500)
}

function copySecret(secret: string) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(secret).then(() => {
      ElMessage.success('已复制到剪贴板')
      markSecretCopied()
    }).catch(() => {
      fallbackCopy(secret)
    })
  } else {
    fallbackCopy(secret)
  }
}

function fallbackCopy(text: string) {
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  try {
    document.execCommand('copy')
    ElMessage.success('已复制到剪贴板')
    markSecretCopied()
  } catch {
    ElMessage.error('复制失败，请手动选择文本复制')
  } finally {
    document.body.removeChild(textarea)
  }
}

function openAppDrawer(app: AdminApp) {
  if (appDrawerTimer) { window.clearTimeout(appDrawerTimer); appDrawerTimer = undefined }
  appDrawerApp.value = app
  fillCallbackForm(app)
  appDrawerVisible.value = true
  requestAnimationFrame(() => requestAnimationFrame(() => {
    appDrawerOpen.value = true
  }))
}

function closeAppDrawer() {
  if (!appDrawerVisible.value) return
  appDrawerOpen.value = false
  if (appDrawerTimer) window.clearTimeout(appDrawerTimer)
  appDrawerTimer = window.setTimeout(() => {
    appDrawerVisible.value = false
    appDrawerApp.value = null
    appDrawerTimer = undefined
  }, 300)
}

function openDeleteAppModal(app: AdminApp) {
  deleteAppTarget.value = app
  deleteAppConfirmId.value = ''
  deleteAppOpen.value = true
}

/* 会话重置时清理本域状态（对应原 resetAdminState 的应用域字段） */
function resetAppsState() {
  apps.value = []
  callbackForm.appId = ''
  callbackForm.callbackUrl = ''
  callbackForm.ttlSeconds = 2
  callbackForm.ttlUnit = 'h'
  callbackForm.neverExpire = false
  callbackForm.isActive = true
  if (appDrawerTimer) { window.clearTimeout(appDrawerTimer); appDrawerTimer = undefined }
  appDrawerOpen.value = false
  appDrawerVisible.value = false
  appDrawerApp.value = null
  deleteAppOpen.value = false
  showCreateAppDialog.value = false
  showSecretDialog.value = false
  secretCopied.value = false
  latestSecretAppId.value = ''
}

registerSessionHooks({ reset: resetAppsState, load: loadApps })

export function disposeApps() {
  if (secretCopiedTimer) { window.clearTimeout(secretCopiedTimer); secretCopiedTimer = undefined }
  if (appDrawerTimer) { window.clearTimeout(appDrawerTimer); appDrawerTimer = undefined }
}

export function useApps() {
  return {
    loadingApps,
    creatingApp,
    savingCallback,
    resettingSecret,
    deletingApp,
    apps,
    latestCreatedAppSecret,
    latestSecretAppId,
    showSecretDialog,
    secretCopied,
    showCreateAppDialog,
    activeAppsCount,
    disabledAppsCount,
    createAppForm,
    callbackForm,
    selectedApp,
    appDrawerVisible,
    appDrawerOpen,
    appDrawerApp,
    deleteAppOpen,
    deleteAppTarget,
    deleteAppConfirmId,
    secretSavedConfirmed,
    resetCreateAppForm,
    openCreateAppDialog,
    loadApps,
    handleCreateApp,
    handleResetSecret,
    handleDeleteApp,
    fillCallbackForm,
    onAppSelected,
    handleSaveCallback,
    saveCallbackFromDrawer,
    markSecretCopied,
    copySecret,
    openAppDrawer,
    closeAppDrawer,
    openDeleteAppModal,
  }
}
