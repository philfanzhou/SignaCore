<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessageBox } from 'element-plus'
import { handleLogout, session, appTitle, handleApiError } from '../composables/useSession'
import { adminClient } from '../services/apiClient'
import {
  getErrorMessage,
  type AdminApp,
  type AdminAuditLogItem,
  type AdminExchangeTrust,
  type AdminLoginHistoryItem,
  type AdminSetting,
  type AdminUser,
  type BootstrapSettings,
} from '../services/adminApi'
import { formatDate, getInitials } from '../utils/format'

type ViewKey = 'overview' | 'identity' | 'resources' | 'security' | 'settings' | 'boundary'
type UserMode = 'password' | 'phone'
type AppTab = 'overview' | 'access' | 'trust' | 'danger'
type ModalKey = 'create-user' | 'create-app' | 'secret' | 'token' | 'session' | 'delete-app' | 'reset-secret' | null
type NavItem = { key: ViewKey; label: string; mark: string; hint: string }

const navGroups: { label: string; items: NavItem[] }[] = [
  {
    label: '工作台',
    items: [{ key: 'overview' as const, label: '运行总览', mark: '◈', hint: '状态与待办' }],
  },
  {
    label: '身份目录',
    items: [{ key: 'identity' as const, label: '账户目录', mark: '◎', hint: '用户与登录历史' }],
  },
  {
    label: '接入资源',
    items: [{ key: 'resources' as const, label: '应用与策略', mark: '▦', hint: 'OAuth 与身份源' }],
  },
  {
    label: '安全中心',
    items: [{ key: 'security' as const, label: '审计与会话', mark: '⌁', hint: '操作记录与撤销' }],
  },
  {
    label: '系统',
    items: [
      { key: 'settings' as const, label: '运行配置', mark: '◌', hint: '配置版本与引导' },
      { key: 'boundary' as const, label: '能力边界', mark: '△', hint: '当前版本说明' },
    ],
  },
]

const activeView = ref<ViewKey>('overview')
const navOpen = ref(false)
const sessionMenuOpen = ref(false)
const initialLoading = ref(true)
const consoleError = ref('')
const toast = ref('')
let toastTimer: number | undefined

const users = ref<AdminUser[]>([])
const userTotal = ref(0)
const userPage = ref(1)
const userPageSize = 12
const userLoading = ref(false)
const userError = ref('')
const userFilters = reactive({ username: '', phone: '', status: 'all' as 'all' | 'active' | 'disabled' })
const selectedUser = ref<AdminUser | null>(null)
const userDrawerOpen = ref(false)
const userDrawerTab = ref<'profile' | 'history'>('profile')
const userHistory = ref<AdminLoginHistoryItem[]>([])
const userHistoryTotal = ref(0)
const userHistoryLoading = ref(false)
const userMeta = reactive({ displayName: '', nickname: '', remark: '' })

const userMode = ref<UserMode>('password')
const userModalOpen = ref(false)
const userSaving = ref(false)
const createUserForm = reactive({ username: '', password: '', phone: '', displayName: '', nickname: '', remark: '' })

const apps = ref<AdminApp[]>([])
const appsLoading = ref(false)
const appsError = ref('')
const appQuery = reactive({ search: '', status: 'all' as 'all' | 'active' | 'disabled', mode: 'all' })
const appPage = ref(1)
const appPageSize = 8
const selectedAppIds = ref<string[]>([])
const selectedApp = ref<AdminApp | null>(null)
const appDrawerOpen = ref(false)
const appTab = ref<AppTab>('overview')
const appSaving = ref(false)
const appDetailLoading = ref(false)
const appConfig = reactive({
  callbackUrl: '',
  ttlSeconds: 86400,
  isActive: true,
  ldapLoginMode: 'Disabled' as AdminApp['ldapLoginMode'],
  smsLoginMode: 'Disabled' as AdminApp['smsLoginMode'],
  smsProfileKey: '',
  wechatLoginMode: 'Disabled' as AdminApp['wechatLoginMode'],
  audienceMode: 'Shared' as AdminApp['audienceMode'],
})
const smsProfiles = ref<{ key: string; provider: string }[]>([])
const ldapDirectories = ref<{ key: string; isDefault: boolean }[]>([])
const appSmsUsers = ref<{ loginId: string; phone: string; isActive: boolean; createdAt: number }[]>([])
const appWechatUsers = ref<{ loginId: string; openId: string; isActive: boolean; createdAt: number }[]>([])
const appLdapUsers = ref<{ credentialId: string; username: string; directoryKey: string; isActive: boolean; createdAt: number }[]>([])
const appTrusts = ref<AdminExchangeTrust[]>([])
const accessLoading = ref(false)
const accessForm = reactive({ phone: '', directoryKey: '', username: '' })
const trustSourceAppId = ref('')

const appModalOpen = ref(false)
const appSavingNew = ref(false)
const createAppForm = reactive({ appName: '', callbackUrl: '', ttlSeconds: 86400 })
const modal = ref<ModalKey>(null)
const secretValue = ref('')
const secretAcknowledged = ref(false)
const deleteConfirmId = ref('')
const tokenValue = ref('')
const destructiveBusy = ref(false)

const auditLogs = ref<AdminAuditLogItem[]>([])
const auditTotal = ref(0)
const auditPage = ref(1)
const auditPageSize = 15
const auditLoading = ref(false)
const auditError = ref('')
const auditFilters = reactive({ action: '', targetType: '', targetId: '' })

const settings = ref<AdminSetting[]>([])
const settingsLoading = ref(false)
const settingsSaving = ref(false)
const settingsError = ref('')
const settingsDraft = reactive<Record<string, string>>({})
const configurationVersion = ref(0)
const runningConfigurationVersion = ref(0)
const restartPending = ref(false)
const bootstrapSettings = ref<BootstrapSettings | null>(null)
const bootstrapLoading = ref(false)
const bootstrapSaving = ref(false)
const bootstrapTesting = ref(false)
const bootstrapMessage = ref('')
const bootstrapError = ref('')
const bootstrapForm = reactive({
  provider: '',
  serverVersion: '',
  endpoint: '',
  filePath: '',
  host: '',
  port: '',
  database: '',
  username: '',
  password: '',
  connectionString: '',
  masterKey: '',
  confirm: false,
})

const activeNavLabel = computed(() => navGroups.flatMap(group => group.items).find(item => item.key === activeView.value)?.label ?? '运行总览')
const activeUsers = computed(() => users.value.filter(user => user.isActive).length)
const activeApps = computed(() => apps.value.filter(app => app.isActive).length)
const disabledApps = computed(() => apps.value.filter(app => !app.isActive).length)
const filteredUsers = computed(() => {
  if (userFilters.status === 'active') return users.value.filter(user => user.isActive)
  if (userFilters.status === 'disabled') return users.value.filter(user => !user.isActive)
  return users.value
})
const userPages = computed(() => Math.max(1, Math.ceil(userTotal.value / userPageSize)))
const filteredApps = computed(() => apps.value.filter(app => {
  const search = appQuery.search.trim().toLowerCase()
  const textMatches = !search || `${app.appName} ${app.appId} ${app.callbackUrl}`.toLowerCase().includes(search)
  const statusMatches = appQuery.status === 'all' || (appQuery.status === 'active' ? app.isActive : !app.isActive)
  const modeMatches = appQuery.mode === 'all' || app.ldapLoginMode === appQuery.mode || app.smsLoginMode === appQuery.mode || app.wechatLoginMode === appQuery.mode
  return textMatches && statusMatches && modeMatches
}))
const appPages = computed(() => Math.max(1, Math.ceil(filteredApps.value.length / appPageSize)))
const appPageItems = computed(() => filteredApps.value.slice((appPage.value - 1) * appPageSize, appPage.value * appPageSize))
const allVisibleAppsSelected = computed(() => appPageItems.value.length > 0 && appPageItems.value.every(app => selectedAppIds.value.includes(app.appId)))
const changedSettings = computed(() => settings.value.filter(setting => {
  if (!(setting.key in settingsDraft)) return false
  const value = settingsDraft[setting.key] ?? ''
  return setting.isSecret ? value.trim().length > 0 : value !== (setting.value ?? '')
}))
const settingGroups = computed(() => {
  const map = new Map<string, AdminSetting[]>()
  for (const setting of settings.value) {
    const prefix = setting.key.split(':')[0] || '其他'
    map.set(prefix, [...(map.get(prefix) ?? []), setting])
  }
  return [...map.entries()].map(([name, items]) => ({ name, items }))
})
const auditPages = computed(() => Math.max(1, Math.ceil(auditTotal.value / auditPageSize)))
const hasBootstrapForm = computed(() => Boolean(bootstrapSettings.value?.editable))

function notify(message: string) {
  toast.value = message
  if (toastTimer) window.clearTimeout(toastTimer)
  toastTimer = window.setTimeout(() => { toast.value = '' }, 3600)
}

function navigate(view: ViewKey) {
  activeView.value = view
  navOpen.value = false
  sessionMenuOpen.value = false
  if (view === 'security' && !auditLogs.value.length) void loadAuditLogs()
}

function formatMode(mode: string) {
  return ({ Disabled: '关闭', ManualApproval: '人工准入', AutoProvision: '自动开户', BindRequired: '需绑定' } as Record<string, string>)[mode] ?? mode
}

function formatEvent(event: string) {
  return ({ login_success: '登录成功', login_failure: '登录失败', admin_login: '管理员登录', logout: '退出登录' } as Record<string, string>)[event] ?? event
}

function formatValue(setting: AdminSetting) {
  if (setting.isSecret) return setting.hasValue ? '已配置（不会回显）' : '未配置'
  if (setting.valueType === 'Boolean') return setting.value === 'true' ? '启用' : '停用'
  return setting.value || '空'
}

function resetUserForm() {
  Object.assign(createUserForm, { username: '', password: '', phone: '', displayName: '', nickname: '', remark: '' })
}

function resetAppForm() {
  Object.assign(createAppForm, { appName: '', callbackUrl: '', ttlSeconds: 86400 })
}

async function loadUsers() {
  userLoading.value = true
  userError.value = ''
  try {
    const result = await adminClient.getUsers({
      username: userFilters.username.trim() || undefined,
      phone: userFilters.phone.trim() || undefined,
      page: userPage.value,
      pageSize: userPageSize,
    })
    users.value = result.items
    userTotal.value = result.total
    if (userPage.value > Math.max(1, Math.ceil(result.total / userPageSize))) userPage.value = 1
    if (selectedUser.value) {
      selectedUser.value = result.items.find(item => item.userId === selectedUser.value?.userId) ?? selectedUser.value
    }
  } catch (error) {
    userError.value = getErrorMessage(error)
    handleApiError('加载账户目录失败', error)
  } finally {
    userLoading.value = false
  }
}

function searchUsers() {
  userPage.value = 1
  void loadUsers()
}

function changeUserPage(page: number) {
  userPage.value = Math.min(Math.max(page, 1), userPages.value)
  void loadUsers()
}

async function saveUser() {
  if (userMode.value === 'password' && (!createUserForm.username.trim() || createUserForm.password.length < 8)) {
    notify('请输入用户名，并设置至少 8 位密码')
    return
  }
  if (userMode.value === 'phone' && !/^1[3-9]\d{9}$/.test(createUserForm.phone.trim())) {
    notify('请输入有效的中国大陆手机号')
    return
  }
  userSaving.value = true
  try {
    if (userMode.value === 'password') {
      await adminClient.createUser({
        username: createUserForm.username.trim(), password: createUserForm.password,
        displayName: createUserForm.displayName.trim() || undefined,
        nickname: createUserForm.nickname.trim() || undefined,
        remark: createUserForm.remark.trim() || undefined,
      })
    } else {
      await adminClient.createPhoneUser({
        phone: createUserForm.phone.trim(),
        displayName: createUserForm.displayName.trim() || undefined,
        nickname: createUserForm.nickname.trim() || undefined,
        remark: createUserForm.remark.trim() || undefined,
      })
    }
    userModalOpen.value = false
    resetUserForm()
    notify('账户已创建')
    await loadUsers()
  } catch (error) {
    handleApiError('创建账户失败', error)
  } finally {
    userSaving.value = false
  }
}

function openUser(user: AdminUser) {
  selectedUser.value = user
  userDrawerTab.value = 'profile'
  Object.assign(userMeta, { displayName: user.displayName || '', nickname: user.nickname || '', remark: user.remark || '' })
  userHistory.value = []
  userHistoryTotal.value = 0
  userDrawerOpen.value = true
  void loadUserHistory()
}

async function loadUserHistory() {
  if (!selectedUser.value) return
  userHistoryLoading.value = true
  try {
    const result = await adminClient.getUserLoginHistory(selectedUser.value.userId, { page: 1, pageSize: 10 })
    userHistory.value = result.items
    userHistoryTotal.value = result.total
  } catch (error) {
    handleApiError('加载登录历史失败', error)
  } finally {
    userHistoryLoading.value = false
  }
}

async function updateUserMeta(field: 'nickname' | 'remark') {
  if (!selectedUser.value) return
  try {
    if (field === 'nickname') await adminClient.updateUserNickname(selectedUser.value.userId, userMeta.nickname.trim())
    else await adminClient.updateUserRemark(selectedUser.value.userId, userMeta.remark.trim())
    notify('账户资料已保存')
    await loadUsers()
  } catch (error) {
    handleApiError('保存账户资料失败', error)
  }
}

async function toggleUser(user: AdminUser) {
  const action = user.isActive ? '禁用' : '启用'
  try {
    await ElMessageBox.confirm(`确认${action}账户「${user.username || user.displayName || user.userId}」？`, `${action}账户`, {
      confirmButtonText: action, cancelButtonText: '取消', type: user.isActive ? 'warning' : 'info',
    })
    await adminClient.updateUserStatus(user.userId, !user.isActive)
    notify(`账户已${action}`)
    await loadUsers()
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') handleApiError(`${action}账户失败`, error)
  }
}

async function loadApps() {
  appsLoading.value = true
  appsError.value = ''
  try {
    apps.value = await adminClient.getApps()
    if (appPage.value > appPages.value) appPage.value = 1
    selectedAppIds.value = selectedAppIds.value.filter(id => apps.value.some(app => app.appId === id))
  } catch (error) {
    appsError.value = getErrorMessage(error)
    handleApiError('加载应用目录失败', error)
  } finally {
    appsLoading.value = false
  }
}

function syncAppForm(app: AdminApp) {
  Object.assign(appConfig, {
    callbackUrl: app.callbackUrl || '',
    ttlSeconds: app.callbackExpiresAt ? Math.max(1, app.callbackExpiresAt - Math.floor(Date.now() / 1000)) : 86400,
    isActive: app.isActive,
    ldapLoginMode: app.ldapLoginMode,
    smsLoginMode: app.smsLoginMode,
    smsProfileKey: app.smsProfileKey || '',
    wechatLoginMode: app.wechatLoginMode,
    audienceMode: app.audienceMode,
  })
}

async function openApp(app: AdminApp) {
  selectedApp.value = app
  appTab.value = 'overview'
  syncAppForm(app)
  appDrawerOpen.value = true
  appDetailLoading.value = true
  void loadAppAccess(app.appId)
  try {
    const [trusts, profiles, directories] = await Promise.all([
      adminClient.getExchangeTrusts(app.appId), adminClient.getSmsProfiles(), adminClient.getLdapDirectories(),
    ])
    appTrusts.value = trusts
    smsProfiles.value = profiles
    ldapDirectories.value = directories
    accessForm.directoryKey = directories.find(item => item.isDefault)?.key ?? directories[0]?.key ?? ''
  } catch (error) {
    handleApiError('加载应用策略失败', error)
  } finally {
    appDetailLoading.value = false
  }
}

async function loadAppAccess(appId: string) {
  accessLoading.value = true
  try {
    const [sms, wechat, ldap] = await Promise.all([
      adminClient.getAppSmsUsers(appId), adminClient.getAppWechatUsers(appId), adminClient.getAppLdapUsers(appId),
    ])
    appSmsUsers.value = sms
    appWechatUsers.value = wechat
    appLdapUsers.value = ldap
  } catch (error) {
    handleApiError('加载应用准入列表失败', error)
  } finally {
    accessLoading.value = false
  }
}

async function saveAppConfig() {
  if (!selectedApp.value) return
  appSaving.value = true
  try {
    // Backend exposes separate policy endpoints. Keep writes sequential so a failed operation is
    // visible and the following refresh never presents an optimistic all-or-nothing state.
    await adminClient.updateCallback(selectedApp.value.appId, {
      callbackUrl: appConfig.callbackUrl.trim() || undefined,
      ttlSeconds: Math.max(0, Number(appConfig.ttlSeconds) || 0), isActive: appConfig.isActive,
    })
    await adminClient.updateLdapPolicy(selectedApp.value.appId, appConfig.ldapLoginMode)
    await adminClient.updateSmsPolicy(selectedApp.value.appId, appConfig.smsLoginMode, appConfig.smsProfileKey || null)
    await adminClient.updateWechatPolicy(selectedApp.value.appId, appConfig.wechatLoginMode)
    await adminClient.updateAudienceMode(selectedApp.value.appId, appConfig.audienceMode)
    notify('应用配置已保存')
    await loadApps()
    selectedApp.value = apps.value.find(app => app.appId === selectedApp.value?.appId) ?? selectedApp.value
    if (selectedApp.value) syncAppForm(selectedApp.value)
  } catch (error) {
    handleApiError('保存应用配置失败，已完成的单项可能已生效', error)
    await loadApps()
  } finally {
    appSaving.value = false
  }
}

async function createApp() {
  if (!createAppForm.appName.trim() || Number(createAppForm.ttlSeconds) < 0) {
    notify('请输入应用名称和有效的回调 TTL')
    return
  }
  appSavingNew.value = true
  try {
    const created = await adminClient.createApp({
      appName: createAppForm.appName.trim(), callbackUrl: createAppForm.callbackUrl.trim() || undefined,
      ttlSeconds: Math.max(0, Number(createAppForm.ttlSeconds) || 0),
    })
    appModalOpen.value = false
    secretValue.value = created.appSecret
    secretAcknowledged.value = false
    modal.value = 'secret'
    resetAppForm()
    await loadApps()
  } catch (error) {
    handleApiError('注册应用失败', error)
  } finally {
    appSavingNew.value = false
  }
}

async function resetAppSecret() {
  if (!selectedApp.value) return
  destructiveBusy.value = true
  try {
    const result = await adminClient.resetAppSecret(selectedApp.value.appId)
    secretValue.value = result.appSecret
    secretAcknowledged.value = false
    modal.value = 'secret'
    notify('新 Secret 已生成，旧 Secret 已失效')
  } catch (error) {
    handleApiError('重置 Secret 失败', error)
  } finally {
    destructiveBusy.value = false
  }
}

async function deleteApp() {
  if (!selectedApp.value || deleteConfirmId.value.trim() !== selectedApp.value.appId) return
  destructiveBusy.value = true
  try {
    await adminClient.deleteApp(selectedApp.value.appId)
    notify('应用已删除，当前后端没有恢复接口')
    closeAppDrawer()
    modal.value = null
    await loadApps()
  } catch (error) {
    handleApiError('删除应用失败', error)
  } finally {
    destructiveBusy.value = false
  }
}

function toggleAppSelection(appId: string) {
  selectedAppIds.value = selectedAppIds.value.includes(appId)
    ? selectedAppIds.value.filter(id => id !== appId)
    : [...selectedAppIds.value, appId]
}

function toggleVisibleApps() {
  if (allVisibleAppsSelected.value) selectedAppIds.value = selectedAppIds.value.filter(id => !appPageItems.value.some(app => app.appId === id))
  else selectedAppIds.value = [...new Set([...selectedAppIds.value, ...appPageItems.value.map(app => app.appId)])]
}

function showUnsupported(message: string) {
  notify(`当前后端暂不支持：${message}`)
}

async function addSmsUser() {
  if (!selectedApp.value || !/^1[3-9]\d{9}$/.test(accessForm.phone.trim())) return notify('请输入有效手机号')
  try {
    await adminClient.addAppSmsUser(selectedApp.value.appId, accessForm.phone.trim())
    accessForm.phone = ''
    await loadAppAccess(selectedApp.value.appId)
    notify('短信准入已添加')
  } catch (error) { handleApiError('添加短信准入失败', error) }
}

async function revokeSmsUser(loginId: string) {
  if (!selectedApp.value) return
  try {
    await ElMessageBox.confirm('撤销后该手机号不能通过当前应用的短信登录。', '撤销短信准入', { confirmButtonText: '撤销', cancelButtonText: '取消', type: 'warning' })
    await adminClient.revokeAppSmsUser(selectedApp.value.appId, loginId)
    await loadAppAccess(selectedApp.value.appId)
    notify('短信准入已撤销')
  } catch (error) { if (error !== 'cancel' && error !== 'close') handleApiError('撤销短信准入失败', error) }
}

async function addLdapUser() {
  if (!selectedApp.value || !accessForm.directoryKey || !accessForm.username.trim()) return notify('请选择目录并输入域账号')
  try {
    await adminClient.addAppLdapUser(selectedApp.value.appId, accessForm.directoryKey, accessForm.username.trim())
    accessForm.username = ''
    await loadAppAccess(selectedApp.value.appId)
    notify('LDAP 准入已添加')
  } catch (error) { handleApiError('添加 LDAP 准入失败', error) }
}

async function revokeLdapUser(credentialId: string) {
  if (!selectedApp.value) return
  try {
    await ElMessageBox.confirm('撤销后该域账号不能通过当前应用的 LDAP 登录。', '撤销 LDAP 准入', { confirmButtonText: '撤销', cancelButtonText: '取消', type: 'warning' })
    await adminClient.revokeAppLdapUser(selectedApp.value.appId, credentialId)
    await loadAppAccess(selectedApp.value.appId)
    notify('LDAP 准入已撤销')
  } catch (error) { if (error !== 'cancel' && error !== 'close') handleApiError('撤销 LDAP 准入失败', error) }
}

async function addTrust() {
  if (!selectedApp.value || !trustSourceAppId.value.trim()) return notify('请输入来源 App ID')
  try {
    await ElMessageBox.confirm('信任关系会让来源应用签发的 refresh token 可以换取当前应用会话，请确认权限边界已核对。', '添加换票信任', { confirmButtonText: '确认添加', cancelButtonText: '取消', type: 'warning' })
    await adminClient.addExchangeTrust(selectedApp.value.appId, trustSourceAppId.value.trim())
    trustSourceAppId.value = ''
    appTrusts.value = await adminClient.getExchangeTrusts(selectedApp.value.appId)
    notify('换票信任已添加')
  } catch (error) { if (error !== 'cancel' && error !== 'close') handleApiError('添加换票信任失败', error) }
}

async function removeTrust(trust: AdminExchangeTrust) {
  if (!selectedApp.value) return
  try {
    await ElMessageBox.confirm('撤销信任不会结束已经换出的当前应用会话。', '撤销换票信任', { confirmButtonText: '撤销', cancelButtonText: '取消', type: 'warning' })
    await adminClient.removeExchangeTrust(selectedApp.value.appId, trust.sourceAppId)
    appTrusts.value = await adminClient.getExchangeTrusts(selectedApp.value.appId)
    notify('换票信任已撤销')
  } catch (error) { if (error !== 'cancel' && error !== 'close') handleApiError('撤销换票信任失败', error) }
}

async function loadAuditLogs() {
  auditLoading.value = true
  auditError.value = ''
  try {
    const result = await adminClient.getAuditLogs({
      action: auditFilters.action.trim() || undefined,
      targetType: auditFilters.targetType || undefined,
      targetId: auditFilters.targetId.trim() || undefined,
      page: auditPage.value, pageSize: auditPageSize,
    })
    auditLogs.value = result.items
    auditTotal.value = result.total
  } catch (error) {
    auditError.value = getErrorMessage(error)
    handleApiError('加载审计日志失败', error)
  } finally { auditLoading.value = false }
}

function searchAudit() { auditPage.value = 1; void loadAuditLogs() }

async function revokeToken() {
  if (!tokenValue.value.trim()) return notify('请输入完整 refresh token')
  destructiveBusy.value = true
  try {
    await adminClient.revokeRefreshToken(tokenValue.value.trim())
    tokenValue.value = ''
    modal.value = null
    notify('refresh token 已撤销')
    if (activeView.value === 'security') void loadAuditLogs()
  } catch (error) { handleApiError('撤销 refresh token 失败', error) }
  finally { destructiveBusy.value = false }
}

async function loadSettings() {
  settingsLoading.value = true
  settingsError.value = ''
  try {
    const result = await adminClient.getSettings()
    settings.value = result.items
    configurationVersion.value = result.configurationVersion
    runningConfigurationVersion.value = result.runningConfigurationVersion
    restartPending.value = result.restartPending
    for (const key of Object.keys(settingsDraft)) delete settingsDraft[key]
    for (const setting of result.items) if (!setting.isSecret) settingsDraft[setting.key] = setting.value ?? ''
  } catch (error) {
    settingsError.value = getErrorMessage(error)
    handleApiError('加载运行配置失败', error)
  } finally { settingsLoading.value = false }
}

async function saveSettings() {
  if (!changedSettings.value.length) return
  settingsSaving.value = true
  try {
    const values: Record<string, string> = {}
    for (const setting of changedSettings.value) values[setting.key] = settingsDraft[setting.key] ?? ''
    const result = await adminClient.updateSettings(values)
    restartPending.value = result.restartRequired
    notify(result.message)
    await loadSettings()
  } catch (error) { handleApiError('保存运行配置失败', error) }
  finally { settingsSaving.value = false }
}

function discardSettings() {
  for (const setting of settings.value) settingsDraft[setting.key] = setting.isSecret ? '' : setting.value ?? ''
  notify('已撤销未保存修改')
}

async function loadBootstrap() {
  bootstrapLoading.value = true
  try {
    const result = await adminClient.getBootstrapSettings()
    bootstrapSettings.value = result
    Object.assign(bootstrapForm, {
      provider: result.provider, serverVersion: result.serverVersion ?? '', endpoint: result.endpoint, filePath: result.filePath,
    })
  } catch (error) {
    // Development fallback instances legitimately do not expose a writable bootstrap file.
    bootstrapError.value = getErrorMessage(error)
  } finally { bootstrapLoading.value = false }
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
  }
}

async function testBootstrapSettings() {
  if (!bootstrapForm.confirm) return notify('测试前请确认你理解数据库目标切换影响')
  bootstrapTesting.value = true
  bootstrapError.value = ''
  try {
    const result = await adminClient.testBootstrapSettings(bootstrapPayload())
    bootstrapMessage.value = `${result.message} 目标：${result.endpoint}`
  } catch (error) { bootstrapError.value = getErrorMessage(error) }
  finally { bootstrapTesting.value = false }
}

async function saveBootstrapSettings() {
  if (!bootstrapForm.confirm) return notify('保存前必须明确确认，服务会重启')
  bootstrapSaving.value = true
  bootstrapError.value = ''
  try {
    const result = await adminClient.updateBootstrapSettings(bootstrapPayload())
    bootstrapMessage.value = result.message
    notify('数据库引导配置已保存，服务将重启')
  } catch (error) { bootstrapError.value = getErrorMessage(error) }
  finally { bootstrapSaving.value = false }
}

async function loadInitial() {
  initialLoading.value = true
  consoleError.value = ''
  const results = await Promise.allSettled([loadUsers(), loadApps(), loadSettings(), loadBootstrap()])
  if (results.every(result => result.status === 'rejected')) consoleError.value = '核心管理数据暂时无法加载，请检查会话和服务状态。'
  initialLoading.value = false
}

function closeAppDrawer() {
  appDrawerOpen.value = false
  selectedApp.value = null
  appTrusts.value = []
  appSmsUsers.value = []
  appWechatUsers.value = []
  appLdapUsers.value = []
}

function closeUserDrawer() {
  userDrawerOpen.value = false
  selectedUser.value = null
}

function closeModal() {
  if (modal.value === 'secret' && !secretAcknowledged.value) return notify('请确认已安全保存 Secret 后关闭')
  modal.value = null
  deleteConfirmId.value = ''
  tokenValue.value = ''
  sessionMenuOpen.value = false
}

function copySecret() {
  if (!secretValue.value) return
  if (navigator.clipboard && window.isSecureContext) {
    void navigator.clipboard.writeText(secretValue.value).then(() => notify('Secret 已复制'))
  } else notify('当前环境不支持自动复制，请手动选择')
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    if (modal.value) closeModal()
    else if (appDrawerOpen.value) closeAppDrawer()
    else if (userDrawerOpen.value) closeUserDrawer()
    else navOpen.value = false
  }
}

watch(() => appQuery.search + appQuery.status + appQuery.mode, () => { appPage.value = 1 })

onMounted(() => {
  window.addEventListener('keydown', onKeydown)
  void loadInitial()
})

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
  if (toastTimer) window.clearTimeout(toastTimer)
})
</script>

<template>
  <div class="console-shell">
    <aside class="console-sidebar" :class="{ open: navOpen }" aria-label="管理端主导航">
      <div class="console-brand">
        <div class="console-brand-mark">SC</div>
        <div>
          <strong>{{ appTitle }}</strong>
          <span>Identity operations</span>
        </div>
      </div>

      <nav class="console-nav">
        <div v-for="group in navGroups" :key="group.label" class="console-nav-group">
          <div class="console-nav-label">{{ group.label }}</div>
          <button
            v-for="item in group.items"
            :key="item.key"
            class="console-nav-item"
            :class="{ active: activeView === item.key }"
            :aria-current="activeView === item.key ? 'page' : undefined"
            @click="navigate(item.key)"
          >
            <span class="console-nav-mark" aria-hidden="true">{{ item.mark }}</span>
            <span class="console-nav-copy"><b>{{ item.label }}</b><small>{{ item.hint }}</small></span>
          </button>
        </div>
      </nav>

      <div class="console-sidebar-footer">
        <div class="console-signal"><span></span>管理会话已建立</div>
        <button class="console-account-mini" @click="modal = 'session'">
          <span class="console-avatar">{{ getInitials(session?.username || 'A').slice(0, 2) }}</span>
          <span><b>{{ session?.username || '管理员' }}</b><small>配置管理员</small></span>
          <span class="console-more">•••</span>
        </button>
      </div>
    </aside>

    <div v-if="navOpen" class="console-backdrop" @click="navOpen = false"></div>

    <section class="console-main">
      <header class="console-header">
        <button class="console-menu-button" aria-label="打开导航" @click="navOpen = !navOpen">☰</button>
        <div class="console-location"><span>SignaCore /</span><strong>{{ activeNavLabel }}</strong></div>
        <div class="console-header-actions">
          <span class="console-environment"><i></i>内部环境</span>
          <button class="console-header-icon" title="刷新当前数据" @click="loadInitial">↻</button>
          <button class="console-user-button" @click="modal = 'session'">
            <span class="console-avatar small">{{ getInitials(session?.username || 'A').slice(0, 2) }}</span>
            <span class="console-user-name">{{ session?.username || '管理员' }}</span>
            <span>⌄</span>
          </button>
        </div>
      </header>

      <main class="console-content">
        <div v-if="initialLoading" class="console-loading-page" role="status"><span class="console-spinner"></span><p>正在读取管理目录…</p></div>
        <div v-else-if="consoleError" class="console-state error-state"><div class="console-state-icon">!</div><h2>管理数据不可用</h2><p>{{ consoleError }}</p><button class="console-button primary" @click="loadInitial">重新加载</button></div>

        <template v-else>
          <section v-if="activeView === 'overview'" class="console-view">
            <div class="console-page-heading"><div><p class="console-eyebrow">CONTROL PLANE / {{ new Date().getFullYear() }}</p><h1>运行总览</h1><p>把身份、接入资源和变更风险放在同一张工作台上。</p></div><button class="console-button secondary" @click="navigate('boundary')">查看能力边界 <span>→</span></button></div>
            <div class="console-metric-grid">
              <article class="console-metric"><span class="metric-label">账户目录</span><strong>{{ userTotal }}</strong><span class="metric-foot success">{{ activeUsers }} 个当前页已启用</span></article>
              <article class="console-metric"><span class="metric-label">接入应用</span><strong>{{ apps.length }}</strong><span class="metric-foot" :class="activeApps ? 'success' : 'muted'">{{ activeApps }} 个对外可用</span></article>
              <article class="console-metric"><span class="metric-label">待处理信号</span><strong>{{ (restartPending ? 1 : 0) + disabledApps }}</strong><span class="metric-foot" :class="restartPending ? 'warning' : 'muted'">{{ restartPending ? '配置等待重启' : '暂无配置重启' }}</span></article>
              <article class="console-metric dark"><span class="metric-label">运行配置版本</span><strong>v{{ configurationVersion }}</strong><span class="metric-foot">运行中 v{{ runningConfigurationVersion }}</span></article>
            </div>
            <div class="console-two-column">
              <article class="console-panel attention-panel"><div class="panel-heading"><div><p class="console-eyebrow">ATTENTION QUEUE</p><h2>需要关注</h2></div><span class="console-count">{{ (restartPending ? 1 : 0) + disabledApps }}</span></div><div v-if="restartPending" class="console-attention-item warning"><span>!</span><div><b>运行配置等待重启</b><p>新的配置版本已经写入，但当前进程仍运行在 v{{ runningConfigurationVersion }}。</p></div><button @click="navigate('settings')">查看</button></div><div v-if="disabledApps" class="console-attention-item"><span>○</span><div><b>{{ disabledApps }} 个应用已停用</b><p>确认是否仍保留对应的回调和准入配置。</p></div><button @click="navigate('resources')">查看</button></div><div v-if="!restartPending && !disabledApps" class="console-empty-inline"><span>✓</span>目前没有待处理信号</div></article>
              <article class="console-panel"><div class="panel-heading"><div><p class="console-eyebrow">RECENT ACTIVITY</p><h2>最近审计</h2></div><button class="text-button" @click="navigate('security')">全部记录 →</button></div><div v-if="auditLogs.length" class="activity-list"><div v-for="item in auditLogs.slice(0, 5)" :key="`${item.createdAt}-${item.action}`" class="activity-row"><span class="activity-dot"></span><div><b>{{ item.description || item.action }}</b><p>{{ item.actorName || '系统' }} · {{ formatDate(item.createdAt) }}</p></div></div></div><div v-else class="console-empty-inline">打开安全中心加载最近审计记录</div></article>
            </div>
            <article class="console-panel state-panel"><div class="panel-heading"><div><p class="console-eyebrow">STATE LANGUAGE</p><h2>状态语言</h2></div><span class="panel-note">统一反馈，避免误判</span></div><div class="state-grid"><div><span class="status-pill green"><i></i>已启用</span><small>可继续操作</small></div><div><span class="status-pill amber"><i></i>等待重启</span><small>变更已保存</small></div><div><span class="status-pill gray"><i></i>未配置</span><small>需要补齐</small></div><div><span class="status-pill red"><i></i>错误</span><small>可重试或联系维护者</small></div></div></article>
          </section>

          <section v-else-if="activeView === 'identity'" class="console-view">
            <div class="console-page-heading"><div><p class="console-eyebrow">IDENTITY DIRECTORY</p><h1>账户目录</h1><p>管理平台账户状态，并在详情中核对登录历史。</p></div><div class="heading-actions"><button class="console-button secondary" @click="userMode = 'phone'; resetUserForm(); userModalOpen = true">＋ 手机账户</button><button class="console-button primary" @click="userMode = 'password'; resetUserForm(); userModalOpen = true">＋ 密码账户</button></div></div>
            <article class="console-panel list-panel">
              <div class="filter-bar"><div class="console-search"><span>⌕</span><input v-model="userFilters.username" placeholder="用户名" @keyup.enter="searchUsers"></div><div class="console-search"><span>⌕</span><input v-model="userFilters.phone" placeholder="手机号" @keyup.enter="searchUsers"></div><select v-model="userFilters.status" class="console-select" aria-label="账户状态"><option value="all">全部状态</option><option value="active">已启用</option><option value="disabled">已禁用</option></select><button class="console-button secondary compact" @click="searchUsers">搜索</button><span class="filter-spacer"></span><button class="console-button ghost compact" @click="showUnsupported('用户批量状态变更和导出')">批量操作</button></div>
              <div class="list-summary"><span>当前页 {{ filteredUsers.length }} / 共 {{ userTotal }} 个账户</span><span>状态筛选仅作用于当前服务端分页结果</span></div>
              <div v-if="userLoading" class="console-table-state"><span class="console-spinner"></span>读取账户目录…</div><div v-else-if="userError" class="console-table-state error">{{ userError }} <button class="text-button" @click="loadUsers">重试</button></div><div v-else-if="!filteredUsers.length" class="console-table-state"><span class="big-state-icon">◎</span><b>没有匹配账户</b><small>调整筛选条件或创建一个新账户。</small></div>
              <div v-else class="console-table-scroll"><table class="console-table"><thead><tr><th>账户</th><th>账号类型</th><th>联系方式</th><th>创建时间</th><th>状态</th><th></th></tr></thead><tbody><tr v-for="user in filteredUsers" :key="user.userId" tabindex="0" @click="openUser(user)" @keydown.enter="openUser(user)"><td><div class="table-primary"><span class="console-avatar table-avatar">{{ getInitials(user.username || user.displayName || '?').slice(0, 2) }}</span><span><b>{{ user.displayName || user.username || user.userId }}</b><small class="mono">{{ user.username || user.userId }}</small></span></div></td><td><span class="status-pill blue">{{ user.hasPassword ? '密码账户' : '手机账户' }}</span></td><td class="mono">{{ user.phone || '—' }}</td><td>{{ formatDate(user.createdAt) }}</td><td><button class="status-pill-button" :class="user.isActive ? 'green' : 'gray'" @click.stop="toggleUser(user)"><i></i>{{ user.isActive ? '已启用' : '已禁用' }}</button></td><td class="row-arrow">→</td></tr></tbody></table></div>
              <div class="console-pager"><span>第 {{ userPage }} / {{ userPages }} 页</span><button :disabled="userPage <= 1" @click="changeUserPage(userPage - 1)">←</button><button :disabled="userPage >= userPages" @click="changeUserPage(userPage + 1)">→</button></div>
            </article>
          </section>

          <section v-else-if="activeView === 'resources'" class="console-view">
            <div class="console-page-heading"><div><p class="console-eyebrow">RESOURCE REGISTRY</p><h1>应用与策略</h1><p>以应用为边界集中管理回调、登录准入、换票信任和生命周期。</p></div><div class="heading-actions"><button class="console-button ghost" @click="showUnsupported('应用列表服务端分页与导出')">导出说明</button><button class="console-button primary" @click="resetAppForm(); appModalOpen = true">＋ 注册应用</button></div></div>
            <article class="console-panel list-panel">
              <div class="filter-bar"><div class="console-search wide"><span>⌕</span><input v-model="appQuery.search" placeholder="搜索应用名称、App ID 或回调地址"></div><select v-model="appQuery.status" class="console-select" aria-label="应用状态"><option value="all">全部状态</option><option value="active">已启用</option><option value="disabled">已停用</option></select><select v-model="appQuery.mode" class="console-select" aria-label="准入策略"><option value="all">所有准入策略</option><option value="ManualApproval">人工准入</option><option value="AutoProvision">自动开户</option><option value="BindRequired">需绑定</option><option value="Disabled">关闭</option></select></div>
              <div class="batch-strip" :class="{ active: selectedAppIds.length }"><span>{{ selectedAppIds.length ? `已选择 ${selectedAppIds.length} 个应用` : '选择应用后可查看批量能力边界' }}</span><button v-if="selectedAppIds.length" class="console-button ghost compact" @click="showUnsupported('应用批量启停、批量删除和导出')">批量操作</button><span v-else class="panel-note">当前后端只提供单应用操作</span></div>
              <div v-if="appsLoading" class="console-table-state"><span class="console-spinner"></span>读取应用目录…</div><div v-else-if="appsError" class="console-table-state error">{{ appsError }} <button class="text-button" @click="loadApps">重试</button></div><div v-else-if="!appPageItems.length" class="console-table-state"><span class="big-state-icon">▦</span><b>没有匹配应用</b><small>调整搜索条件或注册一个新的接入资源。</small></div>
              <div v-else class="console-table-scroll"><table class="console-table resource-table"><thead><tr><th class="check-col"><input type="checkbox" :checked="allVisibleAppsSelected" aria-label="选择当前页" @change="toggleVisibleApps"></th><th>应用资源</th><th>回调与受众</th><th>登录准入</th><th>状态</th><th></th></tr></thead><tbody><tr v-for="app in appPageItems" :key="app.appId" tabindex="0" @click="openApp(app)" @keydown.enter="openApp(app)"><td class="check-col" @click.stop><input type="checkbox" :checked="selectedAppIds.includes(app.appId)" :aria-label="`选择 ${app.appName}`" @change="toggleAppSelection(app.appId)"></td><td><div class="table-primary"><span class="resource-glyph">▦</span><span><b>{{ app.appName }}</b><small class="mono">{{ app.appId }}</small></span></div></td><td><span class="mono truncate">{{ app.callbackUrl || '未配置回调' }}</span><small class="table-secondary">aud: {{ app.audience }}</small></td><td><div class="strategy-stack"><span>{{ formatMode(app.ldapLoginMode) }} LDAP</span><span>{{ formatMode(app.smsLoginMode) }} 短信</span><span>{{ formatMode(app.wechatLoginMode) }} 微信</span></div></td><td><span class="status-pill" :class="app.isActive ? 'green' : 'gray'"><i></i>{{ app.isActive ? '已启用' : '已停用' }}</span></td><td class="row-arrow">→</td></tr></tbody></table></div>
              <div class="console-pager"><span>显示 {{ appPageItems.length }} / {{ filteredApps.length }} 个匹配应用</span><button :disabled="appPage <= 1" @click="appPage--">←</button><button :disabled="appPage >= appPages" @click="appPage++">→</button></div>
            </article>
            <div class="console-info-band"><span>ⓘ</span><p>App Secret 只在注册或重置时返回一次。该页面不会把 Secret 写入本地存储，关闭一次性凭据窗口前需要明确确认。</p></div>
          </section>

          <section v-else-if="activeView === 'security'" class="console-view">
            <div class="console-page-heading"><div><p class="console-eyebrow">SECURITY CENTER</p><h1>审计与会话</h1><p>追踪管理操作，必要时按原始 refresh token 撤销会话。</p></div><button class="console-button danger" @click="modal = 'token'">撤销 refresh token</button></div>
            <article class="console-panel list-panel"><div class="panel-heading"><div><p class="console-eyebrow">AUDIT TRAIL</p><h2>审计日志</h2></div><span class="panel-note">后端默认保留 365 天</span></div><div class="filter-bar"><div class="console-search"><span>⌕</span><input v-model="auditFilters.action" placeholder="操作名称" @keyup.enter="searchAudit"></div><select v-model="auditFilters.targetType" class="console-select" aria-label="目标类型"><option value="">所有目标类型</option><option value="Account">账户</option><option value="AppRegistration">应用</option><option value="RefreshToken">Refresh token</option><option value="Bootstrap">引导配置</option></select><div class="console-search"><span>#</span><input v-model="auditFilters.targetId" placeholder="目标 ID" @keyup.enter="searchAudit"></div><button class="console-button secondary compact" @click="searchAudit">筛选</button></div><div v-if="auditLoading" class="console-table-state"><span class="console-spinner"></span>读取审计记录…</div><div v-else-if="auditError" class="console-table-state error">{{ auditError }} <button class="text-button" @click="loadAuditLogs">重试</button></div><div v-else-if="!auditLogs.length" class="console-table-state"><span class="big-state-icon">⌁</span><b>没有审计记录</b><small>调整筛选条件或等待新的管理操作。</small></div><div v-else class="console-table-scroll"><table class="console-table audit-table"><thead><tr><th>时间</th><th>操作</th><th>目标</th><th>执行者</th><th>客户端</th><th>关联 ID</th></tr></thead><tbody><tr v-for="item in auditLogs" :key="`${item.createdAt}-${item.correlationId}`"><td>{{ formatDate(item.createdAt) }}</td><td><b>{{ item.action }}</b><small class="table-secondary">{{ item.description || '—' }}</small></td><td><span class="mono">{{ item.targetType }}</span><small class="table-secondary mono">{{ item.targetId }}</small></td><td>{{ item.actorName || '系统' }}</td><td class="mono">{{ item.clientIp || '—' }}</td><td class="mono">{{ item.correlationId || '—' }}</td></tr></tbody></table></div><div class="console-pager"><span>共 {{ auditTotal }} 条记录</span><button :disabled="auditPage <= 1" @click="auditPage--; loadAuditLogs()">←</button><button :disabled="auditPage >= auditPages" @click="auditPage++; loadAuditLogs()">→</button></div></article>
          </section>

          <section v-else-if="activeView === 'settings'" class="console-view">
            <div class="console-page-heading"><div><p class="console-eyebrow">SYSTEM CONFIGURATION</p><h1>运行配置</h1><p>配置值按后端允许的键提交；Secret 从不回显，空白代表保持不变。</p></div><div class="heading-actions"><button class="console-button secondary" :disabled="!changedSettings.length || settingsSaving" @click="discardSettings">撤销修改</button><button class="console-button primary" :disabled="!changedSettings.length || settingsSaving" @click="saveSettings">{{ settingsSaving ? '保存中…' : `保存 ${changedSettings.length || ''}` }}</button></div></div>
            <div v-if="restartPending" class="console-warning-banner"><span>!</span><div><b>有配置等待重启</b><p>配置版本 v{{ configurationVersion }} 已保存，当前运行版本为 v{{ runningConfigurationVersion }}。所有配置变更都需要服务重启后生效。</p></div></div>
            <article class="console-panel version-panel"><div><span class="console-eyebrow">CONFIGURATION VERSION</span><strong>v{{ configurationVersion }}</strong></div><div><span>运行中</span><b>v{{ runningConfigurationVersion }}</b></div><div><span>变更项</span><b>{{ changedSettings.length }}</b></div></article>
            <div v-if="settingsLoading" class="console-panel console-table-state"><span class="console-spinner"></span>读取运行配置…</div><div v-else-if="settingsError" class="console-panel console-table-state error">{{ settingsError }} <button class="text-button" @click="loadSettings">重试</button></div><div v-else class="settings-groups"><article v-for="group in settingGroups" :key="group.name" class="console-panel settings-group"><div class="panel-heading"><div><p class="console-eyebrow">{{ group.name.toUpperCase() }}</p><h2>{{ group.name }}</h2></div><span class="panel-note">{{ group.items.length }} 项</span></div><div class="settings-list"><label v-for="setting in group.items" :key="setting.key" class="setting-row"><span><b>{{ setting.key }}</b><small>{{ setting.isSecret ? 'Secret：不会回显，留空保持当前值' : `类型：${setting.valueType} · 当前：${formatValue(setting)}` }}</small></span><input v-model="settingsDraft[setting.key]" class="console-input" :type="setting.isSecret ? 'password' : 'text'" :placeholder="setting.isSecret ? '留空表示不变' : '输入配置值'"></label></div></article></div>
            <article class="console-panel bootstrap-panel"><div class="panel-heading"><div><p class="console-eyebrow">BOOTSTRAP TARGET</p><h2>数据库引导配置</h2><p>后端支持读取当前目标、测试候选连接并保存后重启当前实例。</p></div><span class="status-pill" :class="hasBootstrapForm ? 'green' : 'amber'"><i></i>{{ bootstrapLoading ? '读取中' : hasBootstrapForm ? '可编辑' : '不可编辑' }}</span></div><div v-if="bootstrapError" class="inline-error">{{ bootstrapError }}</div><div v-if="bootstrapSettings" class="bootstrap-grid"><label>Provider<input v-model="bootstrapForm.provider" class="console-input" :disabled="!hasBootstrapForm"></label><label>Server version<input v-model="bootstrapForm.serverVersion" class="console-input" :disabled="!hasBootstrapForm"></label><label class="wide-field">当前 endpoint<input v-model="bootstrapForm.endpoint" class="console-input mono" disabled></label><label>SQLite 文件路径<input v-model="bootstrapForm.filePath" class="console-input" :disabled="!hasBootstrapForm"></label><label>Host<input v-model="bootstrapForm.host" class="console-input" :disabled="!hasBootstrapForm"></label><label>Port<input v-model="bootstrapForm.port" class="console-input" :disabled="!hasBootstrapForm"></label><label>Database<input v-model="bootstrapForm.database" class="console-input" :disabled="!hasBootstrapForm"></label><label>Username<input v-model="bootstrapForm.username" class="console-input" :disabled="!hasBootstrapForm"></label><label>Password（只写）<input v-model="bootstrapForm.password" class="console-input" type="password" :disabled="!hasBootstrapForm"></label><label class="wide-field">高级连接字符串（只写）<input v-model="bootstrapForm.connectionString" class="console-input" type="password" :disabled="!hasBootstrapForm"></label><label>目标 Master Key（只写）<input v-model="bootstrapForm.masterKey" class="console-input" type="password" :disabled="!hasBootstrapForm"></label></div><div v-if="bootstrapSettings" class="bootstrap-actions"><label class="confirm-line"><input v-model="bootstrapForm.confirm" type="checkbox" :disabled="!hasBootstrapForm">我确认数据库切换会修改引导文件并重启当前服务</label><div><button class="console-button secondary" :disabled="!hasBootstrapForm || bootstrapTesting || bootstrapSaving" @click="testBootstrapSettings">{{ bootstrapTesting ? '测试中…' : '测试连接' }}</button><button class="console-button danger" :disabled="!hasBootstrapForm || bootstrapTesting || bootstrapSaving" @click="saveBootstrapSettings">{{ bootstrapSaving ? '保存中…' : '保存并重启' }}</button></div></div></article>
          </section>

          <section v-else-if="activeView === 'boundary'" class="console-view">
            <div class="console-page-heading"><div><p class="console-eyebrow">CAPABILITY BOUNDARY</p><h1>能力边界</h1><p>把后端真实支持的操作和规划中的能力分开，避免把设计稿误当成接口承诺。</p></div></div>
            <div class="boundary-grid"><article class="console-panel"><span class="boundary-kicker supported">当前可用</span><h2>已接入真实 API</h2><ul><li>管理员会话登录、续期检查与退出</li><li>账户分页查询、创建、备注/昵称更新、启停和登录历史</li><li>应用注册、回调、TTL、身份源策略与受众模式</li><li>短信/LDAP/微信准入及换票信任管理</li><li>审计日志、原始 refresh token 撤销</li><li>运行配置和数据库引导配置</li></ul></article><article class="console-panel"><span class="boundary-kicker proposed">建议功能</span><h2>当前后端不支持</h2><ul><li>RBAC、角色/权限 CRUD 和委派管理员</li><li>API Scope、Identity Resource 管理</li><li>应用服务端搜索、排序、分页和导出</li><li>refresh token 列表、批量撤销、恢复</li><li>应用删除恢复、批量启停和批量删除</li></ul></article></div><article class="console-panel implementation-note"><div class="panel-heading"><div><p class="console-eyebrow">IMPLEMENTATION RULE</p><h2>前端实现原则</h2></div></div><div class="rule-list"><div><b>01</b><p>没有对应接口的按钮只显示边界说明，不伪造成功反馈。</p></div><div><b>02</b><p>拆分的应用策略接口顺序提交，失败时提示可能存在部分生效并强制刷新。</p></div><div><b>03</b><p>所有 Secret 和数据库密码只进入受控输入，不写入浏览器本地持久化。</p></div></div></article>
          </section>
        </template>
      </main>
    </section>

    <div v-if="toast" class="console-toast" role="status">{{ toast }}</div>

    <div v-if="userDrawerOpen && selectedUser" class="console-overlay-layer" @click.self="closeUserDrawer"><aside class="console-drawer user-drawer" role="dialog" aria-modal="true" aria-label="账户详情"><div class="drawer-header"><div><span class="console-eyebrow">ACCOUNT DETAIL</span><h2>{{ selectedUser.displayName || selectedUser.username || selectedUser.userId }}</h2><p class="mono">{{ selectedUser.userId }}</p></div><button class="close-button" aria-label="关闭账户详情" @click="closeUserDrawer">×</button></div><div class="drawer-tabs"><button :class="{ active: userDrawerTab === 'profile' }" @click="userDrawerTab = 'profile'">账户资料</button><button :class="{ active: userDrawerTab === 'history' }" @click="userDrawerTab = 'history'; loadUserHistory()">登录历史 <span>{{ userHistoryTotal }}</span></button></div><div class="drawer-body"><template v-if="userDrawerTab === 'profile'"><div class="detail-identity"><span class="console-avatar large">{{ getInitials(selectedUser.username || selectedUser.displayName || '?').slice(0, 2) }}</span><div><b>{{ selectedUser.username || '手机账户' }}</b><p>{{ selectedUser.phone || (selectedUser.hasPassword ? '密码已设置' : '未绑定手机号') }}</p></div><span class="status-pill" :class="selectedUser.isActive ? 'green' : 'gray'"><i></i>{{ selectedUser.isActive ? '已启用' : '已禁用' }}</span></div><div class="detail-grid"><div><span>账号类型</span><b>{{ selectedUser.hasPassword ? '密码账户' : '手机账户' }}</b></div><div><span>创建时间</span><b>{{ formatDate(selectedUser.createdAt) }}</b></div></div><label class="drawer-field">昵称<input v-model="userMeta.nickname" class="console-input"><button class="inline-save" @click="updateUserMeta('nickname')">保存</button></label><label class="drawer-field">备注<textarea v-model="userMeta.remark" class="console-input" rows="3"></textarea><button class="inline-save" @click="updateUserMeta('remark')">保存</button></label><div class="drawer-divider"></div><button class="console-button" :class="selectedUser.isActive ? 'danger' : 'secondary'" @click="toggleUser(selectedUser)">{{ selectedUser.isActive ? '禁用账户' : '启用账户' }}</button></template><template v-else><div v-if="userHistoryLoading" class="console-table-state"><span class="console-spinner"></span>读取登录历史…</div><div v-else-if="!userHistory.length" class="console-table-state"><span class="big-state-icon">⌁</span><b>暂无登录历史</b></div><div v-else class="history-list"><div v-for="item in userHistory" :key="`${item.createdAt}-${item.clientIp}-${item.eventType}`" class="history-row"><span class="status-dot" :class="item.eventType.includes('failure') ? 'red' : 'green'"></span><div><b>{{ formatEvent(item.eventType) }} · {{ item.authMethod }}</b><p>{{ item.clientIp || '未知 IP' }} · {{ formatDate(item.createdAt) }}</p><small v-if="item.failureReason" class="danger-text">{{ item.failureReason }}</small></div></div></div></template></div></aside></div>

    <div v-if="appDrawerOpen && selectedApp" class="console-overlay-layer" @click.self="closeAppDrawer"><aside class="console-drawer app-drawer" role="dialog" aria-modal="true" aria-label="应用详情"><div class="drawer-header"><div><span class="console-eyebrow">RESOURCE DETAIL</span><h2>{{ selectedApp.appName }}</h2><p class="mono">{{ selectedApp.appId }}</p></div><button class="close-button" aria-label="关闭应用详情" @click="closeAppDrawer">×</button></div><div class="drawer-tabs"><button :class="{ active: appTab === 'overview' }" @click="appTab = 'overview'">概览与策略</button><button :class="{ active: appTab === 'access' }" @click="appTab = 'access'">准入名单</button><button :class="{ active: appTab === 'trust' }" @click="appTab = 'trust'">信任关系 <span>{{ appTrusts.length }}</span></button><button :class="{ active: appTab === 'danger' }" @click="appTab = 'danger'">危险操作</button></div><div class="drawer-body"><div v-if="appDetailLoading" class="drawer-loading"><span class="console-spinner"></span>加载策略与准入数据…</div><template v-else-if="appTab === 'overview'"><div class="detail-identity"><span class="resource-glyph large">▦</span><div><b>{{ selectedApp.appName }}</b><p class="mono">aud: {{ selectedApp.audience }}</p></div><span class="status-pill" :class="appConfig.isActive ? 'green' : 'gray'"><i></i>{{ appConfig.isActive ? '已启用' : '已停用' }}</span></div><div class="drawer-section"><div class="section-heading"><h3>回调与生命周期</h3><span>PUT /callback</span></div><label class="drawer-field">Callback URL<input v-model="appConfig.callbackUrl" class="console-input" placeholder="https://…"></label><label class="drawer-field">TTL（秒）<input v-model.number="appConfig.ttlSeconds" class="console-input" type="number" min="0"></label><label class="confirm-line"><input v-model="appConfig.isActive" type="checkbox">允许该应用继续发起认证</label></div><div class="drawer-section"><div class="section-heading"><h3>身份源策略</h3><span>拆分接口，顺序提交</span></div><div class="policy-grid"><label>LDAP<select v-model="appConfig.ldapLoginMode" class="console-select"><option value="Disabled">关闭</option><option value="ManualApproval">人工准入</option><option value="AutoProvision">自动开户</option></select></label><label>短信<select v-model="appConfig.smsLoginMode" class="console-select"><option value="Disabled">关闭</option><option value="ManualApproval">人工准入</option><option value="AutoProvision">自动开户</option></select></label><label v-if="appConfig.smsLoginMode !== 'Disabled'">短信 Profile<select v-model="appConfig.smsProfileKey" class="console-select"><option value="">未选择</option><option v-for="profile in smsProfiles" :key="profile.key" :value="profile.key">{{ profile.key }} · {{ profile.provider }}</option></select></label><label>微信<select v-model="appConfig.wechatLoginMode" class="console-select"><option value="Disabled">关闭</option><option value="BindRequired">需绑定</option><option value="AutoProvision">自动开户</option></select></label><label>Audience<select v-model="appConfig.audienceMode" class="console-select"><option value="Shared">共享</option><option value="PerApplication">按应用</option></select></label></div></div><button class="console-button primary full" :disabled="appSaving" @click="saveAppConfig">{{ appSaving ? '保存中…' : '保存应用配置' }}</button></template><template v-else-if="appTab === 'access'"><div class="drawer-section"><div class="section-heading"><h3>短信准入</h3><span>{{ appSmsUsers.length }} 条</span></div><div class="drawer-inline-form"><input v-model="accessForm.phone" class="console-input" placeholder="输入手机号"><button class="console-button secondary compact" @click="addSmsUser">添加</button></div><div v-for="item in appSmsUsers" :key="item.loginId" class="access-row"><span><b>{{ item.phone }}</b><small>{{ formatDate(item.createdAt) }}</small></span><button class="text-button danger-text" @click="revokeSmsUser(item.loginId)">撤销</button></div></div><div class="drawer-section"><div class="section-heading"><h3>LDAP 准入</h3><span>{{ appLdapUsers.length }} 条</span></div><div class="drawer-inline-form"><select v-model="accessForm.directoryKey" class="console-select"><option value="">目录</option><option v-for="directory in ldapDirectories" :key="directory.key" :value="directory.key">{{ directory.key }}</option></select><input v-model="accessForm.username" class="console-input" placeholder="域账号"><button class="console-button secondary compact" @click="addLdapUser">添加</button></div><div v-for="item in appLdapUsers" :key="item.credentialId" class="access-row"><span><b>{{ item.username }}</b><small>{{ item.directoryKey }} · {{ formatDate(item.createdAt) }}</small></span><button class="text-button danger-text" @click="revokeLdapUser(item.credentialId)">撤销</button></div></div><div class="drawer-section"><div class="section-heading"><h3>微信准入</h3><span>{{ appWechatUsers.length }} 条</span></div><div v-if="!appWechatUsers.length" class="console-empty-inline">暂无微信准入记录</div><div v-for="item in appWechatUsers" :key="item.loginId" class="access-row"><span><b class="mono">{{ item.openId }}</b><small>{{ formatDate(item.createdAt) }}</small></span><span class="status-pill" :class="item.isActive ? 'green' : 'gray'"><i></i>{{ item.isActive ? '有效' : '已撤销' }}</span></div></div></template><template v-else-if="appTab === 'trust'"><div class="drawer-section risk-section"><div class="section-heading"><h3>定向换票信任</h3><span>当前应用接受来源应用 token</span></div><p class="section-description">添加信任会扩大当前应用的会话入口。撤销不会结束已经换出的会话。</p><div class="drawer-inline-form"><input v-model="trustSourceAppId" class="console-input mono" placeholder="来源 App ID"><button class="console-button secondary compact" @click="addTrust">添加信任</button></div><div v-if="!appTrusts.length" class="console-empty-inline">暂无信任关系</div><div v-for="trust in appTrusts" :key="trust.sourceAppId" class="access-row"><span><b>{{ trust.sourceAppName }}</b><small class="mono">{{ trust.sourceAppId }} · {{ formatDate(trust.createdAt) }}</small></span><button class="text-button danger-text" @click="removeTrust(trust)">撤销</button></div></div></template><template v-else><div class="danger-callout"><span>!</span><div><b>这些操作不可由当前后端恢复</b><p>删除应用是物理删除；重置 Secret 会立即使旧凭据失效；撤销 refresh token 需要完整原始 token。</p></div></div><div class="danger-actions"><button class="danger-action" @click="modal = 'reset-secret'">重置 App Secret <small>旧 Secret 立即失效</small></button><button class="danger-action" @click="modal = 'delete-app'; deleteConfirmId = ''">删除应用 <small>无恢复接口</small></button><button class="danger-action" @click="modal = 'token'">撤销 refresh token <small>需要粘贴原始 token</small></button></div></template></div></aside></div>

    <div v-if="userModalOpen" class="console-modal-layer" @click.self="userModalOpen = false"><section class="console-modal" role="dialog" aria-modal="true" aria-labelledby="user-modal-title"><div class="modal-header"><div><span class="console-eyebrow">NEW ACCOUNT</span><h2 id="user-modal-title">创建{{ userMode === 'password' ? '密码' : '手机' }}账户</h2></div><button class="close-button" aria-label="关闭" @click="userModalOpen = false">×</button></div><div class="modal-body"><div class="mode-switch"><button :class="{ active: userMode === 'password' }" @click="userMode = 'password'">密码账户</button><button :class="{ active: userMode === 'phone' }" @click="userMode = 'phone'">手机账户</button></div><label v-if="userMode === 'password'">用户名<input v-model="createUserForm.username" class="console-input" autocomplete="off"></label><label v-else>手机号<input v-model="createUserForm.phone" class="console-input" inputmode="tel" placeholder="13800000000"></label><label v-if="userMode === 'password'">初始密码<input v-model="createUserForm.password" class="console-input" type="password" autocomplete="new-password"><small>至少 8 位，且包含大写、小写和数字。</small></label><label>显示名称<input v-model="createUserForm.displayName" class="console-input"></label><label>昵称<input v-model="createUserForm.nickname" class="console-input"></label><label>备注<textarea v-model="createUserForm.remark" class="console-input" rows="3"></textarea></label></div><div class="modal-footer"><button class="console-button secondary" @click="userModalOpen = false">取消</button><button class="console-button primary" :disabled="userSaving" @click="saveUser">{{ userSaving ? '创建中…' : '创建账户' }}</button></div></section></div>

    <div v-if="appModalOpen" class="console-modal-layer" @click.self="appModalOpen = false"><section class="console-modal" role="dialog" aria-modal="true" aria-labelledby="app-modal-title"><div class="modal-header"><div><span class="console-eyebrow">NEW RESOURCE</span><h2 id="app-modal-title">注册应用</h2></div><button class="close-button" aria-label="关闭" @click="appModalOpen = false">×</button></div><div class="modal-body"><div class="console-info-band compact-band"><span>ⓘ</span><p>注册成功后 App Secret 只展示一次，请在受控环境保存。</p></div><label>应用名称<input v-model="createAppForm.appName" class="console-input"></label><label>Callback URL<input v-model="createAppForm.callbackUrl" class="console-input mono" placeholder="https://client.example/callback"></label><label>回调有效期（秒）<input v-model.number="createAppForm.ttlSeconds" class="console-input" type="number" min="0"><small>填 0 表示不设置过期时间。</small></label></div><div class="modal-footer"><button class="console-button secondary" @click="appModalOpen = false">取消</button><button class="console-button primary" :disabled="appSavingNew" @click="createApp">{{ appSavingNew ? '注册中…' : '注册应用' }}</button></div></section></div>

    <div v-if="modal === 'secret'" class="console-modal-layer strict-layer"><section class="console-modal secret-modal" role="dialog" aria-modal="true" aria-labelledby="secret-title"><div class="modal-header"><div><span class="console-eyebrow">ONE-TIME CREDENTIAL</span><h2 id="secret-title">保存新的 App Secret</h2></div></div><div class="modal-body"><div class="secret-warning"><span>!</span><p>此 Secret 只会从后端返回一次。关闭窗口后无法再次查看，请使用受控凭据保管方式保存。</p></div><div class="secret-value"><code>{{ secretValue }}</code><button class="console-button secondary compact" @click="copySecret">复制</button></div><label class="confirm-line"><input v-model="secretAcknowledged" type="checkbox">我已将 Secret 保存到安全位置，可以关闭此窗口</label></div><div class="modal-footer"><button class="console-button primary" :disabled="!secretAcknowledged" @click="closeModal">完成并关闭</button></div></section></div>

    <div v-if="modal === 'reset-secret'" class="console-modal-layer" @click.self="modal = null"><section class="console-modal danger-modal" role="dialog" aria-modal="true" aria-labelledby="reset-title"><div class="modal-header"><div><span class="console-eyebrow">ROTATE CREDENTIAL</span><h2 id="reset-title">重置 App Secret？</h2></div><button class="close-button" aria-label="关闭" @click="modal = null">×</button></div><div class="modal-body"><div class="danger-callout"><span>!</span><div><b>旧 Secret 会立即失效</b><p>所有使用旧凭据的客户端都会认证失败。确认客户端已经准备好切换新 Secret。</p></div></div></div><div class="modal-footer"><button class="console-button secondary" @click="modal = null">取消</button><button class="console-button danger" :disabled="destructiveBusy" @click="modal = null; resetAppSecret()">确认重置</button></div></section></div>

    <div v-if="modal === 'delete-app' && selectedApp" class="console-modal-layer" @click.self="modal = null"><section class="console-modal danger-modal" role="dialog" aria-modal="true" aria-labelledby="delete-title"><div class="modal-header"><div><span class="console-eyebrow">IRREVERSIBLE ACTION</span><h2 id="delete-title">删除 {{ selectedApp.appName }}？</h2></div><button class="close-button" aria-label="关闭" @click="modal = null">×</button></div><div class="modal-body"><div class="danger-callout"><span>!</span><div><b>后端执行物理删除，当前没有恢复接口。</b><p>删除前请确认下游客户端已经迁移或停用。</p></div></div><label>输入 App ID 确认<input v-model="deleteConfirmId" class="console-input mono" :placeholder="selectedApp.appId"></label></div><div class="modal-footer"><button class="console-button secondary" @click="modal = null">取消</button><button class="console-button danger" :disabled="deleteConfirmId !== selectedApp.appId || destructiveBusy" @click="deleteApp">确认删除</button></div></section></div>

    <div v-if="modal === 'token'" class="console-modal-layer" @click.self="modal = null"><section class="console-modal danger-modal" role="dialog" aria-modal="true" aria-labelledby="token-title"><div class="modal-header"><div><span class="console-eyebrow">SESSION REVOCATION</span><h2 id="token-title">撤销 refresh token</h2></div><button class="close-button" aria-label="关闭" @click="modal = null">×</button></div><div class="modal-body"><div class="danger-callout"><span>!</span><div><b>后端只接受完整原始 token</b><p>当前没有 token 列表或批量撤销接口。撤销成功后该 token 不能恢复。</p></div></div><label>原始 refresh token<textarea v-model="tokenValue" class="console-input mono" rows="5" spellcheck="false"></textarea></label></div><div class="modal-footer"><button class="console-button secondary" @click="modal = null">取消</button><button class="console-button danger" :disabled="!tokenValue.trim() || destructiveBusy" @click="revokeToken">确认撤销</button></div></section></div>

    <div v-if="modal === 'session'" class="console-modal-layer" @click.self="modal = null"><section class="console-modal session-modal" role="dialog" aria-modal="true" aria-labelledby="session-title"><div class="modal-header"><div><span class="console-eyebrow">ADMIN SESSION</span><h2 id="session-title">当前管理会话</h2></div><button class="close-button" aria-label="关闭" @click="modal = null">×</button></div><div class="modal-body"><div class="session-card"><span class="console-avatar large">{{ getInitials(session?.username || 'A').slice(0, 2) }}</span><div><b>{{ session?.username || '管理员' }}</b><p>AdminSession · Cookie 会话</p></div><span class="status-pill green"><i></i>有效</span></div><p class="panel-note">退出会话会清理当前浏览器的管理状态，并回到登录页。</p></div><div class="modal-footer"><button class="console-button secondary" @click="modal = null">继续管理</button><button class="console-button danger" @click="modal = null; handleLogout()">退出登录</button></div></section></div>
  </div>
</template>
