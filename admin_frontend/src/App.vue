<script setup lang="ts">
import axios from 'axios'
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  createAdminApiClient,
  getErrorMessage,
  type AdminApp,
  type AdminSession,
  type AdminUser,
} from './services/adminApi'

const appTitle = ref((window as any).__APP_TITLE__ || 'Identity Admin')
const activeTab = ref('users')
const loadingUsers = ref(false)
const loadingApps = ref(false)
const creatingUser = ref(false)
const creatingPhoneUser = ref(false)
const creatingApp = ref(false)
const savingCallback = ref(false)
const revokingToken = ref(false)
const users = ref<AdminUser[]>([])
const apps = ref<AdminApp[]>([])
const userTotal = ref(0)
const page = ref(1)
const pageSize = ref(20)
const latestCreatedAppSecret = ref('')
const showSecretDialog = ref(false)
const secretDialogTitle = ref('')
const resettingSecret = ref(false)
const deletingApp = ref(false)
const isAuthenticated = ref(false)
const checkingSession = ref(true)
const loggingIn = ref(false)
const sidebarOpen = ref(false)
const sidebarCollapsed = ref(localStorage.getItem('sidebarCollapsed') === 'true')
const session = ref<AdminSession | null>(null)
const lastRefreshTime = ref('')

const showCreateUserDialog = ref(false)
const showCreatePhoneUserDialog = ref(false)
const showCreateAppDialog = ref(false)

const client = createAdminApiClient()

const loginForm = reactive({
  username: '',
  password: '',
  rememberMe: true,
})

const navItems = [
  {
    key: 'users',
    label: '用户管理',
    icon: 'M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z',
  },
  {
    key: 'apps',
    label: '应用注册',
    icon: 'M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z',
  },
  {
    key: 'callbacks',
    label: '回调管理',
    icon: 'M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z',
  },
  {
    key: 'tokens',
    label: '令牌管理',
    icon: 'M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z',
  },
]

const currentNavLabel = computed(() => navItems.find((n) => n.key === activeTab.value)?.label ?? '')
const activeAppsCount = computed(() => apps.value.filter((a) => a.isActive).length)
const showWhitelistWarning = computed(() => session.value?.adminUsernamesConfigured === false)
const totalPages = computed(() => Math.ceil(userTotal.value / pageSize.value))
const pageNumbers = computed(() => {
  const total = totalPages.value
  if (total <= 0) return []
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
  const pages: number[] = []
  const current = page.value
  const start = Math.max(1, current - 2)
  const end = Math.min(total, current + 2)
  for (let i = start; i <= end; i++) pages.push(i)
  return pages
})

const userFilters = reactive({
  username: '',
  phone: '',
})

const createUserForm = reactive({
  username: '',
  password: '',
  remark: '',
})

const createPhoneUserForm = reactive({
  phone: '',
  remark: '',
})

const createAppForm = reactive({
  appName: '',
  callbackUrl: '',
  ttlSeconds: 3600,
  neverExpire: false,
})

const callbackForm = reactive({
  appId: '',
  callbackUrl: '',
  ttlSeconds: 3600,
  neverExpire: false,
  isActive: true,
})

const tokenForm = reactive({
  refreshToken: '',
})

const selectedApp = computed(() => apps.value.find((item) => item.appId === callbackForm.appId) ?? null)

function updateRefreshTime() {
  lastRefreshTime.value = new Date().toLocaleTimeString()
}

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
  localStorage.setItem('sidebarCollapsed', String(sidebarCollapsed.value))
}

function resetAdminState() {
  isAuthenticated.value = false
  session.value = null
  users.value = []
  apps.value = []
  userTotal.value = 0
  page.value = 1
  activeTab.value = 'users'
  callbackForm.appId = ''
  callbackForm.callbackUrl = ''
  callbackForm.ttlSeconds = 3600
  callbackForm.neverExpire = false
  callbackForm.isActive = true
  tokenForm.refreshToken = ''
  sidebarOpen.value = false
}

function resetCreateUserForm() {
  createUserForm.username = ''
  createUserForm.password = ''
  createUserForm.remark = ''
}

function resetCreatePhoneUserForm() {
  createPhoneUserForm.phone = ''
  createPhoneUserForm.remark = ''
}

function resetCreateAppForm() {
  createAppForm.appName = ''
  createAppForm.callbackUrl = ''
  createAppForm.ttlSeconds = 3600
  createAppForm.neverExpire = false
}

function openCreateUserDialog() {
  resetCreateUserForm()
  showCreateUserDialog.value = true
}

function openCreatePhoneUserDialog() {
  resetCreatePhoneUserForm()
  showCreatePhoneUserDialog.value = true
}

function openCreateAppDialog() {
  resetCreateAppForm()
  showCreateAppDialog.value = true
}

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401
}

function handleApiError(prefix: string, error: unknown) {
  if (isUnauthorized(error)) {
    resetAdminState()
    ElMessage.error('登录状态已失效，请重新登录。')
    return
  }

  ElMessage.error(`${prefix}: ${getErrorMessage(error)}`)
}

async function restoreSession() {
  checkingSession.value = true
  try {
    session.value = await client.getCurrentSession()
    isAuthenticated.value = true
    await Promise.all([loadUsers(), loadApps()])
  } catch (error) {
    if (!isUnauthorized(error)) {
      ElMessage.error(`会话检查失败: ${getErrorMessage(error)}`)
    }
    resetAdminState()
  } finally {
    checkingSession.value = false
  }
}

async function handleLogin() {
  if (!loginForm.username || !loginForm.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }

  loggingIn.value = true
  try {
    await client.login({
      username: loginForm.username,
      password: loginForm.password,
      rememberMe: loginForm.rememberMe,
    })
    session.value = await client.getCurrentSession()
    isAuthenticated.value = true
    loginForm.username = ''
    loginForm.password = ''
    ElMessage.success('登录成功')
    await Promise.all([loadUsers(), loadApps()])
  } catch (error) {
    ElMessage.error(`登录失败: ${getErrorMessage(error)}`)
  } finally {
    loggingIn.value = false
  }
}

async function handleLogout() {
  try {
    await client.logout()
    ElMessage.success('已退出登录')
  } catch {
    // ignore
  }
  resetAdminState()
}

async function loadUsers() {
  loadingUsers.value = true
  try {
    const result = await client.getUsers({
      username: userFilters.username || undefined,
      phone: userFilters.phone || undefined,
      page: page.value,
      pageSize: pageSize.value,
    })
    users.value = result.items
    userTotal.value = result.total
    updateRefreshTime()
  } catch (error) {
    handleApiError('加载用户列表失败', error)
  } finally {
    loadingUsers.value = false
  }
}

async function loadApps() {
  loadingApps.value = true
  try {
    apps.value = await client.getApps()
    updateRefreshTime()
  } catch (error) {
    handleApiError('加载应用列表失败', error)
  } finally {
    loadingApps.value = false
  }
}

async function handleCreateUser() {
  if (!createUserForm.username || !createUserForm.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }

  creatingUser.value = true
  try {
    await client.createUser({
      username: createUserForm.username,
      password: createUserForm.password,
      remark: createUserForm.remark || undefined,
    })
    ElMessage.success('用户创建成功')
    showCreateUserDialog.value = false
    resetCreateUserForm()
    await loadUsers()
  } catch (error) {
    handleApiError('创建用户失败', error)
  } finally {
    creatingUser.value = false
  }
}

async function handleCreatePhoneUser() {
  if (!createPhoneUserForm.phone) {
    ElMessage.warning('请输入手机号')
    return
  }

  creatingPhoneUser.value = true
  try {
    await client.createPhoneUser({
      phone: createPhoneUserForm.phone,
      remark: createPhoneUserForm.remark || undefined,
    })
    ElMessage.success('手机账号创建成功')
    showCreatePhoneUserDialog.value = false
    resetCreatePhoneUserForm()
    await loadUsers()
  } catch (error) {
    handleApiError('创建手机账号失败', error)
  } finally {
    creatingPhoneUser.value = false
  }
}

async function handleToggleUserStatus(user: AdminUser) {
  const action = user.isActive ? '禁用' : '启用'
  try {
    await ElMessageBox.confirm(
      `确定要${action}用户 "${user.username}" 吗？`,
      '确认操作',
      { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' }
    )
  } catch {
    return
  }

  try {
    await client.updateUserStatus(user.userId, !user.isActive)
    ElMessage.success(`用户已${action}`)
    await loadUsers()
  } catch (error) {
    handleApiError(`${action}用户失败`, error)
  }
}

async function handleUpdateRemark(user: AdminUser) {
  try {
    const { value } = await ElMessageBox.prompt(
      '请输入新备注',
      '更新备注',
      {
        confirmButtonText: '保存',
        cancelButtonText: '取消',
        inputValue: user.remark || '',
        inputValidator: (val) => val.length <= 200 || '备注不能超过200个字符',
      }
    )
    await client.updateUserRemark(user.userId, value)
    ElMessage.success('备注更新成功')
    await loadUsers()
  } catch (e: any) {
    if (e !== 'cancel') handleApiError('更新备注失败', e)
  }
}

async function handleCreateApp() {
  if (!createAppForm.appName) {
    ElMessage.warning('请输入应用名称')
    return
  }

  creatingApp.value = true
  try {
    const result = await client.createApp({
      appName: createAppForm.appName,
      callbackUrl: createAppForm.callbackUrl || undefined,
      ttlSeconds: createAppForm.neverExpire ? -1 : createAppForm.ttlSeconds,
    })
    ElMessage.success('应用创建成功')
    showCreateAppDialog.value = false
    resetCreateAppForm()
    latestCreatedAppSecret.value = result.appSecret
    secretDialogTitle.value = '应用创建成功'
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
    const result = await client.resetAppSecret(app.appId)
    latestCreatedAppSecret.value = result.appSecret
    secretDialogTitle.value = '密钥重置成功'
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
  try {
    await ElMessageBox.confirm(
      `确定要删除应用 "${app.appName}" (${app.appId}) 吗？此操作不可撤销。`,
      '删除应用',
      { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' }
    )
  } catch {
    return
  }

  deletingApp.value = true
  try {
    await client.deleteApp(app.appId)
    ElMessage.success('应用已删除')
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
    callbackForm.ttlSeconds = 3600
  } else {
    callbackForm.neverExpire = false
    callbackForm.ttlSeconds = Math.max(1, Math.floor(app.callbackExpiresAt - Date.now() / 1000))
  }
  callbackForm.isActive = app.isActive
  activeTab.value = 'callbacks'
}

function onAppSelected() {
  if (!callbackForm.appId) return
  const app = apps.value.find(a => a.appId === callbackForm.appId)
  if (app) {
    fillCallbackForm(app)
  }
}

async function handleSaveCallback() {
  if (!callbackForm.appId) {
    ElMessage.warning('请选择一个应用')
    return
  }

  savingCallback.value = true
  try {
    await client.updateCallback(callbackForm.appId, {
      callbackUrl: callbackForm.callbackUrl || undefined,
      ttlSeconds: callbackForm.neverExpire ? -1 : callbackForm.ttlSeconds,
      isActive: callbackForm.isActive,
    })
    ElMessage.success('回调配置保存成功')
    await loadApps()
  } catch (error) {
    handleApiError('保存回调配置失败', error)
  } finally {
    savingCallback.value = false
  }
}

async function handleRevokeToken() {
  if (!tokenForm.refreshToken) {
    ElMessage.warning('请输入要吊销的刷新令牌')
    return
  }

  revokingToken.value = true
  try {
    await client.revokeRefreshToken(tokenForm.refreshToken)
    ElMessage.success('令牌吊销成功')
    tokenForm.refreshToken = ''
  } catch (error) {
    handleApiError('吊销令牌失败', error)
  } finally {
    revokingToken.value = false
  }
}

function handlePageChange(newPage: number) {
  page.value = newPage
  loadUsers()
}

function refreshAll() {
  Promise.all([loadUsers(), loadApps()])
}

function formatDate(dateVal: string | number | null | undefined): string {
  if (!dateVal && dateVal !== 0) return '-'
  try {
    let ts: number
    if (typeof dateVal === 'number') {
      ts = dateVal
    } else {
      const parsed = Number(dateVal)
      ts = isNaN(parsed) ? new Date(dateVal).getTime() / 1000 : parsed
    }
    if (ts < 10000000000) ts *= 1000
    const d = new Date(ts)
    return `${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
  } catch {
    return String(dateVal)
  }
}

function copySecret(secret: string) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(secret).then(() => {
      ElMessage.success('已复制到剪贴板')
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
  } catch {
    ElMessage.error('复制失败，请手动选择文本复制')
  } finally {
    document.body.removeChild(textarea)
  }
}

function getInitials(name: string): string {
  return name ? name.substring(0, 2).toUpperCase() : 'A'
}

onMounted(() => {
  restoreSession()
})
</script>

<template>
  <div v-if="checkingSession" class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="sidebar-logo auth-logo">QZ</div>
        {{ appTitle }}
      </div>
      <div class="auth-card-body">
        <div class="auth-loading">
          <svg class="spinner auth-spinner" viewBox="0 0 50 50">
            <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary-color)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
              <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>正在验证登录状态...</div>
        </div>
      </div>
    </div>
  </div>

  <div v-else-if="!isAuthenticated" class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="sidebar-logo auth-logo">QZ</div>
        欢迎回来
      </div>
      <div class="auth-card-body">
        <div class="auth-subtitle">请登录管理员账号</div>

        <div class="form-group">
          <label>用户名</label>
          <div class="input-wrap">
            <svg class="input-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
            <input v-model="loginForm.username" type="text" placeholder="请输入管理员用户名" :disabled="loggingIn" @keyup.enter="handleLogin">
          </div>
        </div>

        <div class="form-group">
          <label>密码</label>
          <div class="input-wrap">
            <svg class="input-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <input v-model="loginForm.password" type="password" placeholder="请输入密码" :disabled="loggingIn" @keyup.enter="handleLogin">
          </div>
        </div>

        <label class="checkbox-wrap">
          <input v-model="loginForm.rememberMe" type="checkbox" :disabled="loggingIn">
          <span>7天内免登录</span>
        </label>

        <button class="btn btn-primary" :disabled="loggingIn" @click="handleLogin">
          <svg v-if="loggingIn" class="spinner" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          {{ loggingIn ? '登录中...' : '登录' }}
        </button>
      </div>
    </div>
  </div>

  <div v-else class="admin-layout">
    <aside class="sidebar" :class="{ open: sidebarOpen, collapsed: sidebarCollapsed }">
      <div class="sidebar-header">
        <div class="sidebar-logo">QZ</div>
        <span class="sidebar-title">{{ appTitle }}</span>
        <button class="sidebar-toggle" @click="toggleSidebar">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline v-if="sidebarCollapsed" points="9 18 15 12 9 6" />
            <polyline v-else points="15 18 9 12 15 6" />
          </svg>
        </button>
      </div>
      <nav class="sidebar-nav">
        <div class="nav-section">导航</div>
        <div v-for="item in navItems" :key="item.key" class="nav-item" :class="{ active: activeTab === item.key }" @click="activeTab = item.key; sidebarOpen = false">
          <span class="nav-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
              <path :d="item.icon" />
            </svg>
          </span>
          <span class="nav-label">{{ item.label }}</span>
        </div>
      </nav>
      <div class="sidebar-footer">
        <div class="sidebar-footer-user">
          <div class="sidebar-footer-avatar">{{ getInitials(session?.username || 'A') }}</div>
          <div class="sidebar-footer-info">
            <div class="sidebar-footer-name">{{ session?.username || '管理员' }}</div>
            <div class="sidebar-footer-status">{{ lastRefreshTime ? `上次同步 ${lastRefreshTime}` : '会话活跃' }}</div>
          </div>
        </div>
      </div>
    </aside>

    <div class="sidebar-overlay" :class="{ visible: sidebarOpen }" @click="sidebarOpen = false"></div>

    <div class="main-content" :class="{ 'sidebar-collapsed': sidebarCollapsed }">
      <header class="top-header">
        <div class="header-left">
          <button class="sidebar-toggle-btn" @click="sidebarCollapsed ? toggleSidebar() : (sidebarOpen = !sidebarOpen)">
            <svg v-if="sidebarCollapsed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="9 18 15 12 9 6" />
            </svg>
            <svg v-else width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="3" y1="12" x2="21" y2="12" />
              <line x1="3" y1="6" x2="21" y2="6" />
              <line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>
          <span class="header-breadcrumb">{{ currentNavLabel }}</span>
        </div>
        <div class="header-actions">
          <button class="icon-btn" @click="refreshAll">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10" />
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
            </svg>
            刷新
          </button>
          <div class="status-badge connected">
            <span class="status-dot" />
            {{ session?.username || '已认证' }}
          </div>
          <button class="icon-btn btn-logout" @click="handleLogout">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            退出
          </button>
        </div>
      </header>

      <main class="content-area">
        <div v-if="showWhitelistWarning" class="alert alert-warning">
          <svg class="alert-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <div>
            <strong>安全警告</strong><br>
            当前后端尚未配置 <code>AdminWeb:AdminUsernames</code> 白名单，任何有效的密码账号都可以登录管理后台。建议尽快收紧部署配置。
          </div>
        </div>

        <div class="stats-bar">
          <div class="stats-bar-item">
            <span class="stats-bar-value">{{ userTotal }}</span>
            <span class="stats-bar-label">用户总数</span>
          </div>
          <div class="stats-bar-item">
            <span class="stats-bar-value">{{ apps.length }}</span>
            <span class="stats-bar-label">应用总数</span>
          </div>
          <div class="stats-bar-item">
            <span class="stats-bar-value">{{ activeAppsCount }}</span>
            <span class="stats-bar-label">已启用应用</span>
          </div>
        </div>

        <!-- 用户管理 -->
        <div v-if="activeTab === 'users'">
          <div class="page-header">
            <h1 class="page-title">用户管理</h1>
            <p class="page-subtitle">管理系统用户和手机账号</p>
          </div>
          <div class="card table-card">
            <div class="card-header">
              <span>用户列表</span>
              <div class="card-header-actions">
                <button class="btn btn-primary btn-small" @click="openCreateUserDialog">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                  添加密码账户
                </button>
                <button class="btn btn-secondary btn-small" @click="openCreatePhoneUserDialog">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                  添加手机账户
                </button>
              </div>
            </div>
            <div class="card-body">
              <div class="filter-bar">
                <div class="input-wrap filter-input">
                  <input v-model="userFilters.username" type="text" placeholder="搜索用户名" @keyup.enter="loadUsers">
                </div>
                <div class="input-wrap filter-input">
                  <input v-model="userFilters.phone" type="text" placeholder="搜索手机号" @keyup.enter="loadUsers">
                </div>
                <button class="btn btn-secondary btn-small" @click="loadUsers" title="搜索">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                </button>
              </div>

              <table v-if="!loadingUsers" class="data-table">
                <thead>
                  <tr>
                    <th>用户名</th>
                    <th>手机号</th>
                    <th>状态</th>
                    <th>备注</th>
                    <th>创建时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="user in users" :key="user.userId">
                    <td>
                      <div class="cell-user">
                        <div class="cell-avatar">{{ getInitials(user.username) }}</div>
                        <span class="cell-user-name">{{ user.username }}</span>
                      </div>
                    </td>
                    <td>{{ user.phone || '-' }}</td>
                    <td>
                      <span class="tag" :class="user.isActive ? 'tag-success' : 'tag-danger'">
                        {{ user.isActive ? '已启用' : '已禁用' }}
                      </span>
                    </td>
                    <td>{{ user.remark || '-' }}</td>
                    <td>{{ formatDate(user.createdAt) }}</td>
                    <td>
                      <div class="table-actions">
                        <button class="btn btn-link btn-small" @click="handleUpdateRemark(user)">备注</button>
                        <button class="btn btn-link btn-small" :class="user.isActive ? 'btn-link-danger' : 'btn-link-success'" @click="handleToggleUserStatus(user)">
                          {{ user.isActive ? '禁用' : '启用' }}
                        </button>
                      </div>
                    </td>
                  </tr>
                  <tr v-if="users.length === 0">
                    <td colspan="6">
                      <div class="empty-state">
                        <div class="empty-state-icon">
                          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                            <circle cx="9" cy="7" r="4" />
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                          </svg>
                        </div>
                        <div class="empty-state-text">没有找到用户</div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-else class="empty-state">
                <svg class="spinner empty-spinner" viewBox="0 0 50 50">
                  <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary-color)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
                    <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
                  </circle>
                </svg>
                <div class="empty-state-text">加载中...</div>
              </div>

              <div class="pagination-bar">
                <span class="pagination-info">共 {{ userTotal }} 条</span>
                <button class="page-btn" :disabled="page <= 1" @click="handlePageChange(page - 1)">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="15 18 9 12 15 6" />
                  </svg>
                </button>
                <button v-for="p in pageNumbers" :key="p" class="page-btn" :class="{ active: page === p }" @click="handlePageChange(p)">
                  {{ p }}
                </button>
                <button class="page-btn" :disabled="page >= totalPages" @click="handlePageChange(page + 1)">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- 应用注册 -->
        <div v-if="activeTab === 'apps'">
          <div class="page-header">
            <h1 class="page-title">应用注册</h1>
            <p class="page-subtitle">注册和管理 OAuth 应用</p>
          </div>
          <div class="card table-card">
            <div class="card-header">
              <span>应用列表</span>
              <div class="card-header-actions">
                <button class="btn btn-primary btn-small" @click="openCreateAppDialog">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                  添加应用
                </button>
              </div>
            </div>
            <div class="card-body">
              <table v-if="!loadingApps" class="data-table">
                <thead>
                  <tr>
                    <th>应用名称</th>
                    <th>应用ID</th>
                    <th>回调地址</th>
                    <th>状态</th>
                    <th>回调过期时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="app in apps" :key="app.appId">
                    <td>
                      <div class="cell-app-name">
                        <div class="cell-app-icon">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                            <line x1="8" y1="21" x2="16" y2="21" />
                            <line x1="12" y1="17" x2="12" y2="21" />
                          </svg>
                        </div>
                        <span class="cell-user-name">{{ app.appName }}</span>
                      </div>
                    </td>
                    <td><code class="cell-code">{{ app.appId }}</code></td>
                    <td>{{ app.callbackUrl || '-' }}</td>
                    <td>
                      <span class="tag" :class="app.isActive ? 'tag-success' : 'tag-danger'">
                        {{ app.isActive ? '已启用' : '已禁用' }}
                      </span>
                    </td>
                    <td>{{ app.callbackExpiresAt ? formatDate(app.callbackExpiresAt) : (app.callbackUrl ? '永不过期' : '-') }}</td>
                    <td>
                      <div class="table-actions">
                        <button class="btn btn-link btn-small" @click="fillCallbackForm(app)">配置</button>
                        <button class="btn btn-link btn-link-warning btn-small" :disabled="resettingSecret" @click="handleResetSecret(app)">重置</button>
                        <button class="btn btn-link btn-link-danger btn-small" :disabled="deletingApp" @click="handleDeleteApp(app)">删除</button>
                      </div>
                    </td>
                  </tr>
                  <tr v-if="apps.length === 0">
                    <td colspan="6">
                      <div class="empty-state">
                        <div class="empty-state-icon">
                          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                            <line x1="8" y1="21" x2="16" y2="21" />
                            <line x1="12" y1="17" x2="12" y2="21" />
                          </svg>
                        </div>
                        <div class="empty-state-text">没有注册应用</div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-else class="empty-state">
                <svg class="spinner empty-spinner" viewBox="0 0 50 50">
                  <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary-color)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
                    <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
                  </circle>
                </svg>
                <div class="empty-state-text">加载中...</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 回调管理 -->
        <div v-if="activeTab === 'callbacks'">
          <div class="page-header">
            <h1 class="page-title">回调管理</h1>
            <p class="page-subtitle">配置 OAuth 回调地址和过期设置</p>
          </div>
          <div class="card">
            <div class="card-header">
              <span>回调配置</span>
            </div>
            <div class="card-body">
              <div class="callback-grid">
                <div class="form-group">
                  <label>选择应用</label>
                  <div class="select-wrap">
                    <select v-model="callbackForm.appId" @change="onAppSelected">
                      <option value="">请选择应用</option>
                      <option v-for="app in apps" :key="app.appId" :value="app.appId">
                        {{ app.appName }} ({{ app.appId }})
                      </option>
                    </select>
                  </div>
                </div>
                <div class="form-group">
                  <label>回调地址</label>
                  <div class="input-wrap">
                    <input v-model="callbackForm.callbackUrl" type="text" placeholder="留空则清除回调配置">
                  </div>
                </div>
                <div class="form-group">
                  <label>TTL(秒)</label>
                  <div class="input-wrap">
                    <span v-if="callbackForm.neverExpire" class="input-plain input-static">永不过期</span>
                    <input v-else v-model.number="callbackForm.ttlSeconds" type="number" min="1" step="300" class="input-plain">
                  </div>
                </div>
                <div class="form-group">
                  <label>永不过期</label>
                  <div class="switch-wrap">
                    <label class="switch">
                      <input v-model="callbackForm.neverExpire" type="checkbox">
                      <span class="slider" />
                    </label>
                    <span class="switch-label">{{ callbackForm.neverExpire ? '永不过期' : '定时过期' }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label>应用状态</label>
                  <div class="switch-wrap">
                    <label class="switch">
                      <input v-model="callbackForm.isActive" type="checkbox">
                      <span class="slider" />
                    </label>
                    <span class="switch-label">{{ callbackForm.isActive ? '已启用' : '已禁用' }}</span>
                  </div>
                </div>
              </div>

              <div v-if="selectedApp" class="alert alert-info alert-mt">
                <svg class="alert-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="16" x2="12" y2="12" />
                  <line x1="12" y1="8" x2="12.01" y2="8" />
                </svg>
                <div>
                  <strong>已选择: {{ selectedApp.appName }}</strong><br>
                  当前回调: {{ selectedApp.callbackUrl || '未配置' }}, 过期时间: {{ selectedApp.callbackExpiresAt ? formatDate(selectedApp.callbackExpiresAt) : '永不过期' }}
                </div>
              </div>

              <div class="callback-actions">
                <button class="btn btn-primary btn-small" :disabled="savingCallback" @click="handleSaveCallback">
                  <svg v-if="savingCallback" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  {{ savingCallback ? '保存中...' : '保存回调配置' }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- 令牌管理 -->
        <div v-if="activeTab === 'tokens'">
          <div class="page-header">
            <h1 class="page-title">令牌管理</h1>
            <p class="page-subtitle">管理和吊销刷新令牌</p>
          </div>
          <div class="card token-panel">
            <div class="card-header">吊销刷新令牌</div>
            <div class="card-body">
              <div class="alert alert-warning">
                <svg class="alert-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <div>
                  <strong>安全警告</strong><br>
                  吊销刷新令牌将使其立即失效，用户需要重新认证。
                </div>
              </div>
              <div class="form-group">
                <label>刷新令牌</label>
                <textarea v-model="tokenForm.refreshToken" class="input" rows="4" placeholder="粘贴要吊销的刷新令牌" />
              </div>
              <button class="btn btn-danger btn-small" :disabled="revokingToken" @click="handleRevokeToken">
                <svg v-if="revokingToken" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                </svg>
                {{ revokingToken ? '吊销中...' : '吊销令牌' }}
              </button>
            </div>
          </div>
        </div>
      </main>
    </div>

    <!-- 创建用户对话框 -->
    <div v-if="showCreateUserDialog" class="dialog-overlay" @click.self="showCreateUserDialog = false">
      <div class="dialog dialog-narrow">
        <div class="dialog-header">
          <div class="dialog-icon primary">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
          </div>
          创建密码账户
        </div>
        <div class="dialog-body">
          <div class="form-group">
            <label>用户名</label>
            <div class="input-wrap">
              <input v-model="createUserForm.username" type="text" placeholder="请输入用户名" @keyup.enter="handleCreateUser">
            </div>
          </div>
          <div class="form-group">
            <label>密码</label>
            <div class="input-wrap">
              <input v-model="createUserForm.password" type="password" placeholder="请输入密码" @keyup.enter="handleCreateUser">
            </div>
          </div>
          <div class="form-group">
            <label>备注</label>
            <textarea v-model="createUserForm.remark" class="input" rows="2" placeholder="可选备注" />
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-primary btn-small" :disabled="creatingUser" @click="handleCreateUser">
            <svg v-if="creatingUser" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingUser ? '创建中...' : '创建' }}
          </button>
          <button class="btn btn-secondary btn-small" @click="showCreateUserDialog = false">取消</button>
        </div>
      </div>
    </div>

    <!-- 创建手机账号对话框 -->
    <div v-if="showCreatePhoneUserDialog" class="dialog-overlay" @click.self="showCreatePhoneUserDialog = false">
      <div class="dialog dialog-narrow">
        <div class="dialog-header">
          <div class="dialog-icon success">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" />
            </svg>
          </div>
          创建手机账号
        </div>
        <div class="dialog-body">
          <div class="form-group">
            <label>手机号</label>
            <div class="input-wrap">
              <input v-model="createPhoneUserForm.phone" type="text" placeholder="请输入手机号" @keyup.enter="handleCreatePhoneUser">
            </div>
          </div>
          <div class="form-group">
            <label>备注</label>
            <textarea v-model="createPhoneUserForm.remark" class="input" rows="2" placeholder="可选备注" />
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-primary btn-small" :disabled="creatingPhoneUser" @click="handleCreatePhoneUser">
            <svg v-if="creatingPhoneUser" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingPhoneUser ? '创建中...' : '创建' }}
          </button>
          <button class="btn btn-secondary btn-small" @click="showCreatePhoneUserDialog = false">取消</button>
        </div>
      </div>
    </div>

    <!-- 创建应用对话框 -->
    <div v-if="showCreateAppDialog" class="dialog-overlay" @click.self="showCreateAppDialog = false">
      <div class="dialog dialog-narrow">
        <div class="dialog-header">
          <div class="dialog-icon warning">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
          </div>
          创建应用
        </div>
        <div class="dialog-body">
          <div class="form-group">
            <label>应用名称</label>
            <div class="input-wrap">
              <input v-model="createAppForm.appName" type="text" placeholder="请输入应用名称" @keyup.enter="handleCreateApp">
            </div>
          </div>
          <div class="form-group">
            <label>初始回调地址</label>
            <div class="input-wrap">
              <input v-model="createAppForm.callbackUrl" type="text" placeholder="可选">
            </div>
          </div>
          <div class="form-group">
            <label>回调TTL(秒)</label>
            <div class="input-wrap">
              <span v-if="createAppForm.neverExpire" class="input-plain input-static">永不过期</span>
              <input v-else v-model.number="createAppForm.ttlSeconds" type="number" min="1" step="300" class="input-plain">
            </div>
          </div>
          <div class="form-group">
            <label class="checkbox-wrap">
              <input v-model="createAppForm.neverExpire" type="checkbox">
              <span>永不过期</span>
            </label>
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-primary btn-small" :disabled="creatingApp" @click="handleCreateApp">
            <svg v-if="creatingApp" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingApp ? '创建中...' : '创建' }}
          </button>
          <button class="btn btn-secondary btn-small" @click="showCreateAppDialog = false">取消</button>
        </div>
      </div>
    </div>

    <!-- 密钥对话框 -->
    <div v-if="showSecretDialog" class="dialog-overlay" @click.self="showSecretDialog = false">
      <div class="dialog">
        <div class="dialog-header">{{ secretDialogTitle }}</div>
        <div class="dialog-body">
          <div class="alert alert-warning alert-mb-sm">
            <svg class="alert-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <div>应用密钥仅显示一次，请立即复制并妥善保存。</div>
          </div>
          <code class="secret-text">{{ latestCreatedAppSecret }}</code>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-primary btn-small" @click="copySecret(latestCreatedAppSecret)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
            </svg>
            复制密钥
          </button>
          <button class="btn btn-secondary btn-small" @click="showSecretDialog = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>
