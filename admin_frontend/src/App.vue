<script setup lang="ts">
import axios from 'axios'
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
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

/* Linear SVG icons (stroke 1.6) - 与样稿一致 */
const I = {
  grid:   '<rect x="3.5" y="3.5" width="7" height="7" rx="1.8"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.8"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.8"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.8"/>',
  users:  '<circle cx="9" cy="8" r="3.2"/><path d="M3.5 19.5c.6-3.2 2.8-4.8 5.5-4.8s4.9 1.6 5.5 4.8"/><circle cx="17" cy="9" r="2.4"/><path d="M15.6 14.9c2.6.1 4.3 1.5 4.9 4.1"/>',
  app:    '<rect x="4" y="4" width="16" height="16" rx="3.5"/><path d="M9 12h6M12 9v6"/>',
  shield: '<path d="M12 3.5l7 2.6v5.2c0 4.4-2.9 7.6-7 9.2-4.1-1.6-7-4.8-7-9.2V6.1z"/><path d="M9.2 11.8l2 2 3.6-3.8"/>',
  file:   '<path d="M6 3.5h7.5L18.5 9v11a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 20V5A1.5 1.5 0 0 1 6 3.5z"/><path d="M13.5 3.5V9H18.5"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
  upload: '<path d="M12 16V5.5M7.5 9.5L12 5l4.5 4.5"/><path d="M4.5 16.5v2A1.5 1.5 0 0 0 6 20h12a1.5 1.5 0 0 0 1.5-1.5v-2"/>',
  back:   '<path d="M15 5.5L8.5 12l6.5 6.5"/>',
  x:      '<path d="M6 6l12 12M18 6L6 18"/>',
  copy:   '<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M15.5 5.5v-1a2 2 0 0 0-2-2h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h1"/>',
  check:  '<path d="M4.5 12.5l5 5 10-11"/>',
  clock:  '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  refresh:'<path d="M20 12a8 8 0 1 1-2.3-5.6"/><path d="M20 3.5V8h-4.5"/>',
  eye:    '<path d="M2.5 12S6 5.8 12 5.8 21.5 12 21.5 12 18 18.2 12 18.2 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
  alert:  '<path d="M12 4L2.8 19.5h18.4z"/><path d="M12 10v4M12 16.8v.2"/>',
  zap:    '<path d="M13 2.5L4.5 13.5H11l-1 8L18.5 10.5H12z"/>',
  book:   '<path d="M4.5 5.5A2 2 0 0 1 6.5 3.5H19.5v15H6.5a2 2 0 0 0-2 2z"/><path d="M4.5 18.5V5.5"/><path d="M9 8h6"/>',
  image:  '<rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><circle cx="9" cy="10" r="1.8"/><path d="M4.5 17.5l4.5-4.5 3.5 3.5 3-3 4 4"/>',
  chev:   '<path d="M9 6l6 6-6 6"/>',
  menu:   '<path d="M4 7h16M4 12h16M4 17h16"/>',
  logout: '<path d="M14 4.5H7A1.5 1.5 0 0 0 5.5 6v12A1.5 1.5 0 0 0 7 19.5h7"/><path d="M10 12h10M17 8.5l3.5 3.5-3.5 3.5"/>',
  key:    '<circle cx="8" cy="15.5" r="4"/><path d="M11 12.5L20 3.5M16.5 7l3 3M13.8 9.7l2.5 2.5"/>',
  plus:   '<path d="M12 5v14M5 12h14"/>',
  db:     '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.8"/><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13"/><path d="M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>',
  doc:    '<path d="M6 3.5h7.5L18.5 9v11A1.5 1.5 0 0 1 17 21.5H6A1.5 1.5 0 0 1 4.5 20V5A1.5 1.5 0 0 1 6 3.5z"/><path d="M8.5 13h7M8.5 16.5h5"/>',
  warnTri:'<circle cx="12" cy="12" r="8.5"/><path d="M12 8v4.5M12 15.8v.2"/>',
} as const

/* nav 配置 - 与样稿的 4 个 Tab 对应（系统切换器、概览、审计 不实现，见 spec） */
const navItems = [
  { key: 'users',    label: '用户管理', icon: 'users' },
  { key: 'apps',     label: '应用注册', icon: 'app' },
  { key: 'callbacks',label: '回调管理', icon: 'shield' },
  { key: 'tokens',   label: '令牌管理', icon: 'key' },
] as const

const currentNavLabel = computed(() => navItems.find((n) => n.key === activeTab.value)?.label ?? '')
const activeAppsCount = computed(() => apps.value.filter((a) => a.isActive).length)
const disabledAppsCount = computed(() => apps.value.filter((a) => !a.isActive).length)
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

/* 用户列表 chip 筛选（前端筛选当前页数据，不影响 API 参数） */
const userStatusFilter = ref<'all' | 'active' | 'disabled'>('all')
const filteredUsers = computed(() => {
  if (userStatusFilter.value === 'active') return users.value.filter(u => u.isActive)
  if (userStatusFilter.value === 'disabled') return users.value.filter(u => !u.isActive)
  return users.value
})
const activeUsersInPage = computed(() => users.value.filter(u => u.isActive).length)
const disabledUsersInPage = computed(() => users.value.filter(u => !u.isActive).length)

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

const tokenForm = reactive({
  refreshToken: '',
})

const selectedApp = computed(() => apps.value.find((item) => item.appId === callbackForm.appId) ?? null)

/* ============ 抽屉与模态框状态（展示层新增，不调用 API） ============ */
const userDrawerOpen = ref(false)
const userDrawerUser = ref<AdminUser | null>(null)
const userDrawerTab = ref<'info'>('info')

const appDrawerOpen = ref(false)
const appDrawerApp = ref<AdminApp | null>(null)

const editRemarkOpen = ref(false)
const editRemarkTarget = ref<AdminUser | null>(null)
const editRemarkValue = ref('')

const deleteAppOpen = ref(false)
const deleteAppTarget = ref<AdminApp | null>(null)
const deleteAppConfirmId = ref('')

const secretSavedConfirmed = ref(false)

const viewLeaving = ref(false)
const navIndicatorStyle = ref<{ transform: string; opacity: number }>({ transform: 'translateY(0)', opacity: 0 })
const navRef = ref<HTMLElement | null>(null)
const clockText = ref('')
let clockTimer: number | undefined

function updateRefreshTime() {
  lastRefreshTime.value = new Date().toLocaleTimeString()
}

function tickClock() {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  clockText.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function resetAdminState() {
  isAuthenticated.value = false
  session.value = null
  users.value = []
  apps.value = []
  userTotal.value = 0
  page.value = 1
  activeTab.value = 'users'
  userStatusFilter.value = 'all'
  callbackForm.appId = ''
  callbackForm.callbackUrl = ''
  callbackForm.ttlSeconds = 2
  callbackForm.ttlUnit = 'h'
  callbackForm.neverExpire = false
  callbackForm.isActive = true
  tokenForm.refreshToken = ''
  sidebarOpen.value = false
  userDrawerOpen.value = false
  appDrawerOpen.value = false
  editRemarkOpen.value = false
  deleteAppOpen.value = false
  showCreateUserDialog.value = false
  showCreatePhoneUserDialog.value = false
  showCreateAppDialog.value = false
  showSecretDialog.value = false
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
  createAppForm.ttlSeconds = 2
  createAppForm.ttlUnit = 'h'
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
        ? createAppForm.ttlSeconds * 86400
        : createAppForm.ttlSeconds * 3600
    const result = await client.createApp({
      appName: createAppForm.appName,
      callbackUrl: createAppForm.callbackUrl || undefined,
      ttlSeconds,
    })
    ElMessage.success('应用创建成功')
    showCreateAppDialog.value = false
    resetCreateAppForm()
    latestCreatedAppSecret.value = result.appSecret
    secretDialogTitle.value = '应用创建成功'
    secretSavedConfirmed.value = false
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
    secretSavedConfirmed.value = false
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
    await client.deleteApp(app.appId)
    ElMessage.success('应用已删除')
    deleteAppOpen.value = false
    appDrawerOpen.value = false
    deleteAppTarget.value = null
    deleteAppConfirmId.value = ''
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
      callbackForm.ttlSeconds = Math.max(1, Math.floor(remainingSec / 3600))
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

async function handleSaveCallback() {
  if (!callbackForm.appId) {
    ElMessage.warning('请选择一个应用')
    return
  }

  savingCallback.value = true
  try {
    const ttlSeconds = callbackForm.neverExpire
      ? -1
      : callbackForm.ttlUnit === 'd'
        ? callbackForm.ttlSeconds * 86400
        : callbackForm.ttlSeconds * 3600
    await client.updateCallback(callbackForm.appId, {
      callbackUrl: callbackForm.callbackUrl || undefined,
      ttlSeconds,
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

function formatTtl(app: AdminApp): string {
  if (!app.callbackUrl) return '-'
  if (!app.callbackExpiresAt) return '永不过期'
  const remainingSec = Math.max(0, Math.floor(app.callbackExpiresAt - Date.now() / 1000))
  if (remainingSec >= 86400 && remainingSec % 86400 === 0) return `${remainingSec / 86400} 天`
  return `${Math.max(1, Math.floor(remainingSec / 3600))} 小时`
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

/* ============ 展示层交互（不调用 API） ============ */
function navigateTo(tab: string) {
  if (activeTab.value === tab) return
  viewLeaving.value = true
  setTimeout(() => {
    activeTab.value = tab
    viewLeaving.value = false
    sidebarOpen.value = false
    nextTick(() => updateNavIndicator())
  }, 150)
}

function updateNavIndicator() {
  const nav = navRef.value
  if (!nav) {
    navIndicatorStyle.value = { transform: 'translateY(0)', opacity: 0 }
    return
  }
  const active = nav.querySelector('.nav-item.active') as HTMLElement | null
  if (!active) {
    navIndicatorStyle.value = { transform: 'translateY(0)', opacity: 0 }
    return
  }
  navIndicatorStyle.value = {
    transform: `translateY(${active.offsetTop}px)`,
    opacity: 1,
  }
}

function openUserDrawer(user: AdminUser) {
  userDrawerUser.value = user
  userDrawerTab.value = 'info'
  userDrawerOpen.value = true
}

function closeUserDrawer() {
  userDrawerOpen.value = false
  userDrawerUser.value = null
}

function openEditRemarkModal(user: AdminUser) {
  editRemarkTarget.value = user
  editRemarkValue.value = user.remark || ''
  editRemarkOpen.value = true
}

async function saveEditRemark() {
  if (!editRemarkTarget.value) return
  const val = editRemarkValue.value
  if (val.length > 200) {
    ElMessage.warning('备注不能超过200个字符')
    return
  }
  try {
    await client.updateUserRemark(editRemarkTarget.value.userId, val)
    ElMessage.success('备注更新成功')
    editRemarkOpen.value = false
    editRemarkTarget.value = null
    await loadUsers()
  } catch (error) {
    handleApiError('更新备注失败', error)
  }
}

function openAppDrawer(app: AdminApp) {
  appDrawerApp.value = app
  fillCallbackForm(app)
  appDrawerOpen.value = true
}

function closeAppDrawer() {
  appDrawerOpen.value = false
  appDrawerApp.value = null
}

function openDeleteAppModal(app: AdminApp) {
  deleteAppTarget.value = app
  deleteAppConfirmId.value = ''
  deleteAppOpen.value = true
}

/* 数字滚动入场 */
function runCounters(root: HTMLElement | null) {
  if (!root) return
  root.querySelectorAll<HTMLElement>('[data-count]').forEach(elm => {
    const target = parseFloat(elm.dataset.count || '0')
    const dur = 900
    const t0 = performance.now()
    const suffix = elm.dataset.suffix || ''
    const tick = (t: number) => {
      const p = Math.min((t - t0) / dur, 1)
      const e = 1 - Math.pow(1 - p, 3)
      elm.textContent = Math.round(target * e).toLocaleString('en-US') + suffix
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  })
}

const statGridRef = ref<HTMLElement | null>(null)
watch([userTotal, apps, activeAppsCount, disabledAppsCount], () => {
  nextTick(() => runCounters(statGridRef.value))
})

onMounted(() => {
  restoreSession()
  tickClock()
  clockTimer = window.setInterval(tickClock, 1000)
  nextTick(() => updateNavIndicator())
})

onUnmounted(() => {
  if (clockTimer) window.clearInterval(clockTimer)
})

watch(activeTab, () => {
  nextTick(() => updateNavIndicator())
})
</script>

<template>
  <!-- 会话检查中 -->
  <div v-if="checkingSession" class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="auth-logo">QZ</div>
        {{ appTitle }}
      </div>
      <div class="auth-card-body">
        <div class="auth-loading">
          <svg class="spinner auth-spinner" viewBox="0 0 50 50">
            <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
              <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>正在验证登录状态...</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 未登录 -->
  <div v-else-if="!isAuthenticated" class="auth-page">
    <div class="auth-card">
      <div class="auth-card-header">
        <div class="auth-logo">若</div>
        <div>
          欢迎回来
          <div class="auth-card-header-sub">QuantumZhou.Identity 管理控制台</div>
        </div>
      </div>
      <div class="auth-card-body">
        <div class="auth-subtitle">请登录管理员账号</div>

        <div class="field">
          <label>用户名</label>
          <div class="input-wrap">
            <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="9" cy="8" r="3.2"/><path d="M3.5 19.5c.6-3.2 2.8-4.8 5.5-4.8s4.9 1.6 5.5 4.8"/><circle cx="17" cy="9" r="2.4"/><path d="M15.6 14.9c2.6.1 4.3 1.5 4.9 4.1"/>
            </svg>
            <input v-model="loginForm.username" class="input" type="text" placeholder="请输入管理员用户名" :disabled="loggingIn" @keyup.enter="handleLogin">
          </div>
        </div>

        <div class="field">
          <label>密码</label>
          <div class="input-wrap">
            <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="8" cy="15.5" r="4"/><path d="M11 12.5L20 3.5M16.5 7l3 3M13.8 9.7l2.5 2.5"/>
            </svg>
            <input v-model="loginForm.password" class="input" type="password" placeholder="请输入密码" :disabled="loggingIn" @keyup.enter="handleLogin">
          </div>
        </div>

        <label class="check-line">
          <input v-model="loginForm.rememberMe" type="checkbox" :disabled="loggingIn">
          <span>7天内免登录</span>
        </label>

        <button class="btn btn-block" style="margin-top: 16px" :disabled="loggingIn" @click="handleLogin">
          <svg v-if="loggingIn" class="spinner" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          {{ loggingIn ? '登录中...' : '登录' }}
        </button>
      </div>
    </div>
  </div>

  <!-- 已登录主界面 -->
  <div v-else class="app-shell">
    <aside class="sidebar" :class="{ open: sidebarOpen }">
      <div class="brand">
        <div class="brand-mark">若</div>
        <div class="brand-text">若愚学习平台<span>管理控制台</span></div>
      </div>
      <nav class="nav" ref="navRef">
        <div class="nav-indicator" :style="navIndicatorStyle"></div>
        <div class="nav-label">QuantumZhou.Identity</div>
        <button
          v-for="item in navItems"
          :key="item.key"
          class="nav-item"
          :class="{ active: activeTab === item.key }"
          @click="navigateTo(item.key)"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I[item.icon]"></svg>
          <span>{{ item.label }}</span>
        </button>
      </nav>
      <div class="sidebar-foot">
        <div class="admin-chip">
          <div class="avatar">{{ getInitials(session?.username || 'A') }}</div>
          <div>
            <div class="name">{{ session?.username || '管理员' }}</div>
            <div class="role">超级管理员</div>
          </div>
        </div>
      </div>
    </aside>

    <div class="overlay" :class="{ open: sidebarOpen }" @click="sidebarOpen = false"></div>

    <div class="main">
      <header class="topbar">
        <button class="hamburger icon-btn" @click="sidebarOpen = !sidebarOpen">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" v-html="I.menu"></svg>
        </button>
        <div class="crumb">
          <span>身份中心</span>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.chev"></svg>
          <b>{{ currentNavLabel }}</b>
        </div>
        <div class="top-right">
          <button class="icon-btn" title="刷新数据" @click="refreshAll">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.refresh"></svg>
          </button>
          <span class="env-tag">内网环境</span>
          <span class="clock">{{ clockText }}</span>
          <button class="logout-btn" title="退出登录" @click="handleLogout">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.logout"></svg>
          </button>
        </div>
      </header>

      <main class="view-wrap" :class="{ leaving: viewLeaving }">
        <!-- 统计栏 -->
        <div class="stat-grid" ref="statGridRef">
          <div class="card hoverable stat-card">
            <div class="stat-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
              用户总数
            </div>
            <div class="stat-num" :data-count="userTotal">0</div>
            <div class="stat-foot">
              <span>当前页 {{ users.length }} 条</span>
            </div>
          </div>
          <div class="card hoverable stat-card">
            <div class="stat-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
              OAuth 应用
            </div>
            <div class="stat-num" :data-count="apps.length">0</div>
            <div class="stat-foot">{{ activeAppsCount }} 个已启用 · {{ disabledAppsCount }} 个停用</div>
          </div>
          <div class="card hoverable stat-card">
            <div class="stat-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.zap"></svg>
              已启用应用
            </div>
            <div class="stat-num" :data-count="activeAppsCount">0</div>
            <div class="stat-foot">调用方在线接入</div>
          </div>
          <div class="card hoverable stat-card">
            <div class="stat-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.warnTri"></svg>
              已停用应用
            </div>
            <div class="stat-num" :data-count="disabledAppsCount">0</div>
            <div class="stat-foot">需关注 · 检查是否下线</div>
          </div>
        </div>

        <!-- 用户管理 -->
        <div v-if="activeTab === 'users'">
          <div class="page-head">
            <div>
              <div class="page-title">用户管理</div>
              <div class="page-sub">平台账户的开户、检索与处置</div>
            </div>
            <div class="page-actions">
              <button class="btn btn-ghost" @click="openCreatePhoneUserDialog">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.plus"></svg>
                手机账户
              </button>
              <button class="btn" @click="openCreateUserDialog">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.plus"></svg>
                密码账户
              </button>
            </div>
          </div>

          <div class="card">
            <div style="display: flex; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; align-items: center">
              <div class="input-wrap" style="flex: 1; min-width: 220px; max-width: 340px">
                <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.search"></svg>
                <input v-model="userFilters.username" class="input" placeholder="搜索用户名" @keyup.enter="loadUsers">
              </div>
              <div class="input-wrap" style="flex: 1; min-width: 220px; max-width: 340px">
                <svg class="input-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.search"></svg>
                <input v-model="userFilters.phone" class="input" placeholder="搜索手机号" @keyup.enter="loadUsers">
              </div>
              <button class="btn btn-ghost btn-sm" @click="loadUsers" title="搜索">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.search"></svg>
                搜索
              </button>
              <div class="chips">
                <button class="chip" :class="{ active: userStatusFilter === 'all' }" @click="userStatusFilter = 'all'">全部 {{ users.length }}</button>
                <button class="chip" :class="{ active: userStatusFilter === 'active' }" @click="userStatusFilter = 'active'">已启用 {{ activeUsersInPage }}</button>
                <button class="chip" :class="{ active: userStatusFilter === 'disabled' }" @click="userStatusFilter = 'disabled'">已禁用 {{ disabledUsersInPage }}</button>
              </div>
            </div>

            <div v-if="loadingUsers" class="loading-state">
              <svg class="spinner" viewBox="0 0 50 50">
                <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
                  <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
                </circle>
              </svg>
              <div>加载中...</div>
            </div>
            <div v-else-if="filteredUsers.length === 0" class="empty">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
              <br>没有匹配的账户，试试调整筛选条件
            </div>
            <div v-else class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>用户</th>
                    <th>手机号</th>
                    <th>类型</th>
                    <th>备注</th>
                    <th>创建时间</th>
                    <th>状态</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="user in filteredUsers"
                    :key="user.userId"
                    class="clickable"
                    @click="openUserDrawer(user)"
                  >
                    <td>
                      <div class="cell-flex">
                        <div class="cell-avatar" :class="{ disabled: !user.isActive }">{{ getInitials(user.username || user.displayName || '?').slice(0, 1) }}</div>
                        <div>
                          <div class="td-main">{{ user.username || user.displayName || user.userId }}</div>
                          <div class="td-sub mono">{{ user.userId }}</div>
                        </div>
                      </div>
                    </td>
                    <td class="mono" style="font-size: 12.5px">{{ user.phone || '-' }}</td>
                    <td>
                      <span class="badge" :class="user.username ? 'indigo' : 'blue'">
                        <span class="dot"></span>{{ user.username ? '密码账户' : '手机账户' }}
                      </span>
                    </td>
                    <td style="color: var(--text-2); max-width: 200px">{{ user.remark || '-' }}</td>
                    <td style="color: var(--text-3); font-size: 12.5px; font-variant-numeric: tabular-nums">{{ formatDate(user.createdAt) }}</td>
                    <td @click.stop>
                      <label class="switch" :title="user.isActive ? '点击禁用' : '点击启用'">
                        <input type="checkbox" :checked="user.isActive" @change="handleToggleUserStatus(user)">
                        <span class="track"></span>
                      </label>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="pager">
              <span class="total">共 {{ userTotal }} 条</span>
              <button :disabled="page <= 1" @click="handlePageChange(page - 1)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(180deg)">
                  <path d="M9 6l6 6-6 6"/>
                </svg>
              </button>
              <button v-for="p in pageNumbers" :key="p" :class="{ cur: page === p }" @click="handlePageChange(p)">{{ p }}</button>
              <button :disabled="page >= totalPages" @click="handlePageChange(page + 1)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M9 6l6 6-6 6"/>
                </svg>
              </button>
            </div>
          </div>
        </div>

        <!-- 应用注册 -->
        <div v-if="activeTab === 'apps'">
          <div class="page-head">
            <div>
              <div class="page-title">应用注册</div>
              <div class="page-sub">接入平台的业务系统及其 OAuth 配置</div>
            </div>
            <div class="page-actions">
              <button class="btn" @click="openCreateAppDialog">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.plus"></svg>
                注册应用
              </button>
            </div>
          </div>

          <div class="card">
            <div v-if="loadingApps" class="loading-state">
              <svg class="spinner" viewBox="0 0 50 50">
                <circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="80" stroke-dashoffset="60">
                  <animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1s" repeatCount="indefinite" />
                </circle>
              </svg>
              <div>加载中...</div>
            </div>
            <div v-else-if="apps.length === 0" class="empty">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
              <br>没有注册应用
            </div>
            <div v-else class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>应用</th>
                    <th>App ID</th>
                    <th>回调地址</th>
                    <th>回调有效期</th>
                    <th>状态</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="app in apps"
                    :key="app.appId"
                    class="clickable"
                    @click="openAppDrawer(app)"
                  >
                    <td>
                      <div class="cell-flex">
                        <div class="cell-app-icon">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
                        </div>
                        <span class="td-main">{{ app.appName }}</span>
                      </div>
                    </td>
                    <td class="mono" style="color: var(--text-2)">{{ app.appId }}</td>
                    <td style="max-width: 240px">
                      <span class="mono" style="font-size: 12px" :style="{ color: app.callbackUrl ? 'var(--text-2)' : 'var(--text-3)' }">{{ app.callbackUrl || '未配置' }}</span>
                    </td>
                    <td style="font-variant-numeric: tabular-nums">{{ formatTtl(app) }}</td>
                    <td>
                      <span class="badge" :class="app.isActive ? 'green' : 'gray'">
                        <span class="dot"></span>{{ app.isActive ? '已启用' : '已停用' }}
                      </span>
                    </td>
                    <td style="color: var(--text-3); width: 30px">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.chev"></svg>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="card section-gap" style="display: flex; gap: 14px; align-items: center; background: var(--info-soft); border-color: var(--info-line)">
            <div class="alert-ico-box" style="background: #fff; color: var(--info)">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.key"></svg>
            </div>
            <div style="font-size: 12.5px; color: #075985">App Secret 仅在创建或重置时显示一次，平台不做明文存储。需要轮换密钥时请进入应用详情操作，旧 Secret 将立即失效。</div>
          </div>
        </div>

        <!-- 回调管理 -->
        <div v-if="activeTab === 'callbacks'">
          <div class="page-head">
            <div>
              <div class="page-title">回调管理</div>
              <div class="page-sub">配置 OAuth 回调地址和过期设置</div>
            </div>
            <div class="page-actions">
              <button class="btn btn-ghost" :disabled="savingCallback" @click="handleSaveCallback">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.check"></svg>
                保存配置
              </button>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-title">回调配置</div>
                <div class="card-sub">选择应用后填写回调参数</div>
              </div>
            </div>

            <div class="field">
              <label>选择应用</label>
              <select v-model="callbackForm.appId" class="select" style="width: 100%" @change="onAppSelected">
                <option value="">请选择应用</option>
                <option v-for="app in apps" :key="app.appId" :value="app.appId">
                  {{ app.appName }} ({{ app.appId }})
                </option>
              </select>
            </div>

            <div class="field">
              <label>回调地址（Callback URL）</label>
              <input v-model="callbackForm.callbackUrl" class="input" style="width: 100%" placeholder="留空则清除回调配置">
              <div class="hint">留空表示纯服务端应用，不使用浏览器回调。</div>
            </div>

            <div class="field">
              <label>回调有效期</label>
              <div class="input-with-unit">
                <input v-if="!callbackForm.neverExpire" v-model.number="callbackForm.ttlSeconds" class="input" type="number" min="1">
                <input v-else class="input" :value="'永不过期'" disabled>
                <select v-model="callbackForm.ttlUnit" class="select" :disabled="callbackForm.neverExpire">
                  <option value="h">小时</option>
                  <option value="d">天</option>
                </select>
              </div>
              <div class="hint">到期后回调地址自动失效，需重新配置。保存即从此刻重新计时。</div>
            </div>

            <div class="field" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0">
              <label style="margin: 0">永不过期</label>
              <label class="switch">
                <input v-model="callbackForm.neverExpire" type="checkbox">
                <span class="track"></span>
              </label>
            </div>

            <div class="field" style="display: flex; align-items: center; justify-content: space-between; margin-top: 16px; margin-bottom: 0">
              <label style="margin: 0">应用状态</label>
              <label class="switch">
                <input v-model="callbackForm.isActive" type="checkbox">
                <span class="track"></span>
              </label>
            </div>

            <div v-if="selectedApp" class="alert alert-info section-gap">
              <div class="alert-ico-box">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
              </div>
              <div>
                <strong>已选择：{{ selectedApp.appName }}</strong><br>
                当前回调：{{ selectedApp.callbackUrl || '未配置' }}，过期时间：{{ selectedApp.callbackExpiresAt ? formatDate(selectedApp.callbackExpiresAt) : '永不过期' }}
              </div>
            </div>

            <div style="display: flex; justify-content: flex-end; margin-top: 18px">
              <button class="btn" :disabled="savingCallback" @click="handleSaveCallback">
                <svg v-if="savingCallback" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                </svg>
                {{ savingCallback ? '保存中...' : '保存回调配置' }}
              </button>
            </div>
          </div>
        </div>

        <!-- 令牌管理 -->
        <div v-if="activeTab === 'tokens'">
          <div class="page-head">
            <div>
              <div class="page-title">令牌管理</div>
              <div class="page-sub">管理和吊销刷新令牌</div>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-title">吊销刷新令牌</div>
                <div class="card-sub">输入完整的 refresh token 字符串</div>
              </div>
            </div>

            <div class="alert alert-warning">
              <div class="alert-ico-box">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
              </div>
              <div>
                <strong>安全警告</strong><br>
                吊销刷新令牌将使其立即失效，用户需要重新认证。
              </div>
            </div>

            <div class="field">
              <label>刷新令牌</label>
              <textarea v-model="tokenForm.refreshToken" class="input" rows="4" placeholder="粘贴要吊销的刷新令牌"></textarea>
            </div>

            <div style="display: flex; justify-content: flex-end">
              <button class="btn btn-danger" :disabled="revokingToken" @click="handleRevokeToken">
                <svg v-if="revokingToken" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                </svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.logout"></svg>
                {{ revokingToken ? '吊销中...' : '吊销令牌' }}
              </button>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>

  <!-- ============ 用户 Drawer ============ -->
  <template v-if="userDrawerOpen && userDrawerUser">
    <div class="overlay" :class="{ open: userDrawerOpen }" @click="closeUserDrawer"></div>
    <div class="drawer" :class="{ open: userDrawerOpen }">
      <div class="drawer-head">
        <div class="avatar" style="width: 40px; height: 40px; font-size: 14px">{{ getInitials(userDrawerUser.username || userDrawerUser.displayName || '?').slice(0, 1) }}</div>
        <div style="flex: 1">
          <div class="drawer-title">{{ userDrawerUser.username || userDrawerUser.displayName || userDrawerUser.userId }}</div>
          <div class="drawer-sub mono">{{ userDrawerUser.userId }}{{ userDrawerUser.username ? ' · ' + userDrawerUser.username : '' }}</div>
        </div>
        <span class="badge" :class="userDrawerUser.isActive ? 'green' : 'gray'">
          <span class="dot"></span>{{ userDrawerUser.isActive ? '已启用' : '已禁用' }}
        </span>
        <button class="icon-btn" @click="closeUserDrawer">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.x"></svg>
        </button>
      </div>
      <div class="drawer-body">
        <div class="mini-tabs">
          <button class="mini-tab" :class="{ active: userDrawerTab === 'info' }" @click="userDrawerTab = 'info'">基本信息</button>
        </div>
        <div class="card" style="padding: 18px">
          <dl class="kv">
            <dt>手机号</dt>
            <dd class="mono">{{ userDrawerUser.phone || '-' }}</dd>
            <dt>账户类型</dt>
            <dd>{{ userDrawerUser.username ? '密码账户' : '手机账户（短信验证码登录）' }}</dd>
            <dt>备注</dt>
            <dd>
              {{ userDrawerUser.remark || '-' }}
              <button class="btn btn-ghost btn-sm" style="margin-left: 6px" @click="openEditRemarkModal(userDrawerUser)">编辑</button>
            </dd>
            <dt>创建时间</dt>
            <dd style="font-variant-numeric: tabular-nums">{{ formatDate(userDrawerUser.createdAt) }}</dd>
          </dl>
        </div>
      </div>
      <div class="drawer-foot">
        <button class="btn btn-ghost" @click="closeUserDrawer">关闭</button>
        <button
          :class="userDrawerUser.isActive ? 'btn btn-danger' : 'btn'"
          @click="handleToggleUserStatus(userDrawerUser); closeUserDrawer()"
        >
          {{ userDrawerUser.isActive ? '禁用账户' : '启用账户' }}
        </button>
      </div>
    </div>
  </template>

  <!-- ============ 应用 Drawer ============ -->
  <template v-if="appDrawerOpen && appDrawerApp">
    <div class="overlay" :class="{ open: appDrawerOpen }" @click="closeAppDrawer"></div>
    <div class="drawer" :class="{ open: appDrawerOpen }">
      <div class="drawer-head">
        <div class="cell-app-icon" style="width: 40px; height: 40px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
        </div>
        <div style="flex: 1">
          <div class="drawer-title">{{ appDrawerApp.appName }}</div>
          <div class="drawer-sub mono">{{ appDrawerApp.appId }}</div>
        </div>
        <span class="badge" :class="appDrawerApp.isActive ? 'green' : 'gray'">
          <span class="dot"></span>{{ appDrawerApp.isActive ? '已启用' : '已停用' }}
        </span>
        <button class="icon-btn" @click="closeAppDrawer">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.x"></svg>
        </button>
      </div>
      <div class="drawer-body">
        <div class="card" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">回调配置</div>
          <div class="field">
            <label>回调地址（Callback URL）</label>
            <input v-model="callbackForm.callbackUrl" class="input" style="width: 100%" placeholder="https://your-app.example.com/auth/callback">
            <div class="hint">留空表示纯服务端应用，不使用浏览器回调。</div>
          </div>
          <div class="field">
            <label>回调有效期</label>
            <div class="input-with-unit">
              <input v-if="!callbackForm.neverExpire" v-model.number="callbackForm.ttlSeconds" class="input" type="number" min="1">
              <input v-else class="input" :value="'永不过期'" disabled>
              <select v-model="callbackForm.ttlUnit" class="select" :disabled="callbackForm.neverExpire">
                <option value="h">小时</option>
                <option value="d">天</option>
              </select>
            </div>
            <div class="hint">到期后回调地址自动失效，需重新配置。保存即从此刻重新计时。</div>
          </div>
          <div class="field" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0">
            <label style="margin: 0">启用该应用</label>
            <label class="switch">
              <input v-model="callbackForm.isActive" type="checkbox">
              <span class="track"></span>
            </label>
          </div>
        </div>
        <div class="danger-zone section-gap">
          <div class="dz-title">重置密钥</div>
          <div class="dz-desc">生成新的 App Secret，旧 Secret 立即失效。新 Secret 仅显示一次。</div>
          <button class="btn btn-danger btn-sm" :disabled="resettingSecret" @click="handleResetSecret(appDrawerApp)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.refresh"></svg>
            重置密钥
          </button>
          <div class="dz-title" style="margin-top: 14px">删除应用</div>
          <div class="dz-desc">删除后使用该应用接入的所有登录将立即失败。</div>
          <button class="btn btn-danger btn-sm" @click="openDeleteAppModal(appDrawerApp)">删除应用</button>
        </div>
      </div>
      <div class="drawer-foot">
        <button class="btn btn-ghost" @click="closeAppDrawer">取消</button>
        <button class="btn" :disabled="savingCallback" @click="handleSaveCallback">保存配置</button>
      </div>
    </div>
  </template>

  <!-- ============ 创建密码账户 Modal ============ -->
  <template v-if="showCreateUserDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showCreateUserDialog = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
          </div>
          <div>
            <div class="modal-title">创建密码账户</div>
            <div class="modal-sub" style="margin: 2px 0 0">标准账户，用户使用用户名与密码登录</div>
          </div>
        </div>
        <div class="field">
          <label>用户名</label>
          <input v-model="createUserForm.username" class="input" style="width: 100%" placeholder="如 zhang.wei" @keyup.enter="handleCreateUser">
        </div>
        <div class="field">
          <label>初始密码</label>
          <input v-model="createUserForm.password" class="input" type="password" style="width: 100%" placeholder="至少 8 位，建议首登后修改" @keyup.enter="handleCreateUser">
        </div>
        <div class="field">
          <label>备注</label>
          <input v-model="createUserForm.remark" class="input" style="width: 100%" placeholder="如 初二(3)班 英语教师">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="showCreateUserDialog = false">取消</button>
          <button class="btn" :disabled="creatingUser" @click="handleCreateUser">
            <svg v-if="creatingUser" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingUser ? '创建中...' : '创建账户' }}
          </button>
        </div>
      </div>
    </div>
  </template>

  <!-- ============ 创建手机账户 Modal ============ -->
  <template v-if="showCreatePhoneUserDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showCreatePhoneUserDialog = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
          </div>
          <div>
            <div class="modal-title">创建手机账户</div>
            <div class="modal-sub" style="margin: 2px 0 0">免密码账户，用户通过短信验证码登录</div>
          </div>
        </div>
        <div class="field">
          <label>手机号</label>
          <input v-model="createPhoneUserForm.phone" class="input" style="width: 100%" placeholder="11 位手机号" @keyup.enter="handleCreatePhoneUser">
        </div>
        <div class="field">
          <label>备注</label>
          <input v-model="createPhoneUserForm.remark" class="input" style="width: 100%" placeholder="如 家长账号 · 关联学生xxx">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="showCreatePhoneUserDialog = false">取消</button>
          <button class="btn" :disabled="creatingPhoneUser" @click="handleCreatePhoneUser">
            <svg v-if="creatingPhoneUser" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingPhoneUser ? '创建中...' : '创建账户' }}
          </button>
        </div>
      </div>
    </div>
  </template>

  <!-- ============ 注册应用 Modal ============ -->
  <template v-if="showCreateAppDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showCreateAppDialog = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
          </div>
          <div>
            <div class="modal-title">注册应用</div>
            <div class="modal-sub" style="margin: 2px 0 0">为新的业务系统创建 OAuth 接入凭证</div>
          </div>
        </div>
        <div class="field">
          <label>应用名称</label>
          <input v-model="createAppForm.appName" class="input" style="width: 100%" placeholder="如 学生门户" @keyup.enter="handleCreateApp">
        </div>
        <div class="field">
          <label>回调地址（可选）</label>
          <input v-model="createAppForm.callbackUrl" class="input" style="width: 100%" placeholder="https://your-app.example.com/auth/callback">
        </div>
        <div class="field">
          <label>回调有效期</label>
          <div class="input-with-unit">
            <input v-if="!createAppForm.neverExpire" v-model.number="createAppForm.ttlSeconds" class="input" type="number" min="1">
            <input v-else class="input" :value="'永不过期'" disabled>
            <select v-model="createAppForm.ttlUnit" class="select" :disabled="createAppForm.neverExpire">
              <option value="h">小时</option>
              <option value="d">天</option>
            </select>
          </div>
        </div>
        <label class="check-line" style="margin-top: 4px">
          <input v-model="createAppForm.neverExpire" type="checkbox">
          <span>永不过期</span>
        </label>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="showCreateAppDialog = false">取消</button>
          <button class="btn" :disabled="creatingApp" @click="handleCreateApp">
            <svg v-if="creatingApp" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            {{ creatingApp ? '创建中...' : '创建并生成密钥' }}
          </button>
        </div>
      </div>
    </div>
  </template>

  <!-- ============ 密钥显示 Modal ============ -->
  <template v-if="showSecretDialog">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="showSecretDialog = false; secretSavedConfirmed = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico warning">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.key"></svg>
          </div>
          <div>
            <div class="modal-title">{{ secretDialogTitle }}</div>
            <div class="modal-sub" style="margin: 2px 0 0">此密钥仅显示这一次，平台不做明文存储</div>
          </div>
        </div>
        <div class="secret-box">
          <code>{{ latestCreatedAppSecret }}</code>
          <button class="copy-btn" @click="copySecret(latestCreatedAppSecret)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.copy"></svg>
            <span>复制</span>
          </button>
        </div>
        <label class="check-line">
          <input v-model="secretSavedConfirmed" type="checkbox">
          <span>我已将密钥保存到安全位置</span>
        </label>
        <div class="modal-actions">
          <button class="btn" :disabled="!secretSavedConfirmed" @click="showSecretDialog = false; secretSavedConfirmed = false">完成</button>
        </div>
      </div>
    </div>
  </template>

  <!-- ============ 编辑备注 Modal ============ -->
  <template v-if="editRemarkOpen && editRemarkTarget">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="editRemarkOpen = false"></div>
      <div class="modal">
        <div class="modal-title">编辑备注</div>
        <div class="modal-sub">{{ editRemarkTarget.username || editRemarkTarget.displayName || editRemarkTarget.userId }} 的备注信息</div>
        <div class="field">
          <input v-model="editRemarkValue" class="input" style="width: 100%" placeholder="备注内容（不超过 200 字符）" maxlength="200">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="editRemarkOpen = false">取消</button>
          <button class="btn" @click="saveEditRemark">保存</button>
        </div>
      </div>
    </div>
  </template>

  <!-- ============ 删除应用二次确认 Modal ============ -->
  <template v-if="deleteAppOpen && deleteAppTarget">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="deleteAppOpen = false"></div>
      <div class="modal">
        <div class="modal-head-row">
          <div class="modal-head-ico danger">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.alert"></svg>
          </div>
          <div>
            <div class="modal-title">删除应用？</div>
            <div class="modal-sub" style="margin: 2px 0 0">删除后使用 <span class="mono">{{ deleteAppTarget.appId }}</span> 接入的登录将立即失败。请输入应用 ID 确认。</div>
          </div>
        </div>
        <div class="field">
          <input v-model="deleteAppConfirmId" class="input" style="width: 100%" :placeholder="deleteAppTarget.appId">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="deleteAppOpen = false">取消</button>
          <button class="btn btn-danger" :disabled="deleteAppConfirmId !== deleteAppTarget.appId || deletingApp" @click="handleDeleteApp(deleteAppTarget)">
            {{ deletingApp ? '删除中...' : '永久删除' }}
          </button>
        </div>
      </div>
    </div>
  </template>
</template>