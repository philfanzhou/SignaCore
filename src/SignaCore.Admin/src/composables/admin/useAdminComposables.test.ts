import { nextTick, ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  api: {
    getApps: vi.fn(),
    getAppSmsUsers: vi.fn(),
    getAppWechatUsers: vi.fn(),
    getAppLdapUsers: vi.fn(),
    getExchangeTrusts: vi.fn(),
    getSmsProfiles: vi.fn(),
    getLdapDirectories: vi.fn(),
    addAppSmsUser: vi.fn(),
    revokeAppSmsUser: vi.fn(),
    addAppLdapUser: vi.fn(),
    revokeAppLdapUser: vi.fn(),
    revokeAppWechatUser: vi.fn(),
    restoreAppWechatUser: vi.fn(),
    addExchangeTrust: vi.fn(),
    removeExchangeTrust: vi.fn(),
    updateCallback: vi.fn(),
    updateLdapPolicy: vi.fn(),
    updateSmsPolicy: vi.fn(),
    updateWechatPolicy: vi.fn(),
    updateAudienceMode: vi.fn(),
    getAppOidc: vi.fn(),
    updateOidcPolicy: vi.fn(),
    addOidcRedirectUris: vi.fn(),
    removeOidcRedirectUri: vi.fn(),
    createApp: vi.fn(),
    resetAppSecret: vi.fn(),
    deleteApp: vi.fn(),
    getUsers: vi.fn(),
    createUser: vi.fn(),
    createPhoneUser: vi.fn(),
    updateUserNickname: vi.fn(),
    updateUserRemark: vi.fn(),
    updateUserStatus: vi.fn(),
    getUserLoginHistory: vi.fn(),
    getAuditLogs: vi.fn(),
    revokeRefreshToken: vi.fn(),
    getSettings: vi.fn(),
    updateSettings: vi.fn(),
    getBootstrapSettings: vi.fn(),
    testBootstrapSettings: vi.fn(),
    updateBootstrapSettings: vi.fn(),
  },
  confirm: vi.fn(),
  handleApiError: vi.fn(),
  notify: vi.fn(),
}))

vi.mock('../../services/apiClient', () => ({ adminClient: mocks.api }))
vi.mock('../useSession', () => ({ handleApiError: mocks.handleApiError }))
vi.mock('./useAdminFeedback', () => ({ notify: mocks.notify }))
vi.mock('element-plus', () => ({ ElMessageBox: { confirm: mocks.confirm } }))

import type { AdminApp, AdminAppOidc, AdminSetting, AdminUser } from '../../services/adminApi'
import { useAdminAppAccess } from './useAdminAppAccess'
import { useAdminAppOidc } from './useAdminAppOidc'
import { useAdminApps } from './useAdminApps'
import { useAdminSecurity } from './useAdminSecurity'
import { useAdminSettings } from './useAdminSettings'
import { useAdminUsers } from './useAdminUsers'

function app(overrides: Partial<AdminApp> = {}): AdminApp {
  return {
    appId: 'orders',
    appName: 'Orders',
    callbackUrl: 'https://orders.example.test/callback',
    callbackExpiresAt: null,
    isActive: true,
    createdAt: 1_700_000_000,
    ldapLoginMode: 'Disabled',
    smsLoginMode: 'ManualApproval',
    smsProfileKey: 'logging',
    wechatLoginMode: 'Disabled',
    audienceMode: 'Shared',
    audience: 'SignaCore.Services',
    ...overrides,
  }
}

/** 未配置过交互式 OIDC 的应用在服务端就是这套值。 */
function oidc(overrides: Partial<AdminAppOidc> = {}): AdminAppOidc {
  return {
    appId: 'orders',
    clientType: 'Confidential',
    allowAuthorizationCode: false,
    allowedScopes: [],
    allowRefreshToken: false,
    identitySessionMaxAgeSeconds: null,
    audienceMode: 'PerApplication',
    redirectUris: [],
    postLogoutRedirectUris: [],
    ...overrides,
  }
}

function user(overrides: Partial<AdminUser> = {}): AdminUser {
  return {
    userId: 'user-1',
    username: 'alice',
    phone: '',
    isActive: true,
    remark: '',
    nickname: null,
    createdAt: 1_700_000_000,
    displayName: 'Alice',
    hasPassword: true,
    ...overrides,
  }
}

const emptyPage = { items: [], total: 0, page: 1, pageSize: 12 }

beforeEach(() => {
  vi.clearAllMocks()
  for (const method of Object.values(mocks.api)) method.mockResolvedValue(undefined)
  mocks.api.getApps.mockResolvedValue([])
  mocks.api.getAppSmsUsers.mockResolvedValue([])
  mocks.api.getAppWechatUsers.mockResolvedValue([])
  mocks.api.getAppLdapUsers.mockResolvedValue([])
  mocks.api.getExchangeTrusts.mockResolvedValue([])
  mocks.api.getAppOidc.mockResolvedValue(oidc())
  mocks.api.getSmsProfiles.mockResolvedValue([])
  mocks.api.getLdapDirectories.mockResolvedValue([])
  mocks.api.getUsers.mockResolvedValue(emptyPage)
  mocks.api.getUserLoginHistory.mockResolvedValue(emptyPage)
  mocks.api.getAuditLogs.mockResolvedValue(emptyPage)
  mocks.api.getSettings.mockResolvedValue({
    configurationVersion: 1,
    runningConfigurationVersion: 1,
    restartPending: false,
    items: [],
  })
  mocks.confirm.mockResolvedValue(true)
})

describe('admin application control plane', () => {
  it('filters, paginates and selects applications', async () => {
    const state = useAdminApps()
    const disabled = app({ appId: 'billing', appName: 'Billing', isActive: false })
    mocks.api.getApps.mockResolvedValue([app(), disabled])

    await state.loadApps()
    expect(state.filteredApps.value).toHaveLength(2)

    state.appQuery.status = 'active'
    expect(state.filteredApps.value.map((item) => item.appId)).toEqual(['orders'])
    expect(state.appPageItems.value.map((item) => item.appId)).toEqual(['orders'])
  })

  it('loads application details and persists configuration and secrets', async () => {
    const state = useAdminApps()
    const selected = app({ callbackExpiresAt: Math.floor(Date.now() / 1000) + 3600 })
    mocks.api.getApps.mockResolvedValue([selected])
    mocks.api.getLdapDirectories.mockResolvedValue([{ key: 'corp', isDefault: true }])
    mocks.api.createApp.mockResolvedValue({ appSecret: 'new-secret' })
    mocks.api.resetAppSecret.mockResolvedValue({ appSecret: 'rotated-secret' })

    await state.openApp(selected)
    expect(state.appDrawerOpen.value).toBe(true)
    expect(state.accessForm.directoryKey).toBe('corp')

    state.appConfig.callbackUrl = '  https://new.example.test/callback '
    state.appConfig.ttlSeconds = 7200
    await state.saveAppConfig()
    expect(mocks.api.updateCallback).toHaveBeenCalledWith('orders', {
      callbackUrl: 'https://new.example.test/callback',
      ttlSeconds: 7200,
      isActive: true,
    })
    expect(mocks.api.updateAudienceMode).toHaveBeenCalledWith('orders', 'Shared')

    state.appModalOpen.value = true
    state.createAppForm.appName = '  Billing  '
    state.createAppForm.callbackUrl = ' https://billing.example.test/callback '
    await state.createApp()
    expect(mocks.api.createApp).toHaveBeenCalledWith({
      appName: 'Billing',
      callbackUrl: 'https://billing.example.test/callback',
      ttlSeconds: 86400,
    })
    expect(state.secretValue.value).toBe('new-secret')
    expect(state.appActionModal.value).toBe('secret')

    state.secretAcknowledged.value = true
    state.closeActionModal()
    await state.resetAppSecret()
    expect(state.secretValue.value).toBe('rotated-secret')
    expect(state.appActionModal.value).toBe('secret')
  })

  it('requires an exact application id before deletion and clears the drawer', async () => {
    const state = useAdminApps()
    const selected = app()
    state.selectedApp.value = selected
    state.deleteConfirmId.value = 'wrong-id'
    await state.deleteApp()
    expect(mocks.api.deleteApp).not.toHaveBeenCalled()

    state.deleteConfirmId.value = 'orders'
    await state.deleteApp()
    expect(mocks.api.deleteApp).toHaveBeenCalledWith('orders')
    expect(state.selectedApp.value).toBeNull()
    expect(state.appDrawerOpen.value).toBe(false)
  })
})

describe('admin application access', () => {
  it('loads access sources and handles SMS, LDAP and trust mutations', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppAccess(selected)
    mocks.api.getSmsProfiles.mockResolvedValue([{ key: 'logging', provider: 'Logging' }])
    mocks.api.getLdapDirectories.mockResolvedValue([{ key: 'corp', isDefault: false }])
    mocks.api.getExchangeTrusts.mockResolvedValue([{ sourceAppId: 'portal' }])

    await state.loadAppDetails('orders')
    await nextTick()
    expect(state.smsProfiles.value).toHaveLength(1)
    expect(state.ldapDirectories.value[0].key).toBe('corp')
    expect(state.appSmsUsers.value).toEqual([])

    state.accessForm.phone = '13800138000'
    await state.addSmsUser()
    expect(mocks.api.addAppSmsUser).toHaveBeenCalledWith('orders', '13800138000')
    expect(state.accessForm.phone).toBe('')

    state.accessForm.directoryKey = 'corp'
    state.accessForm.username = ' alice '
    await state.addLdapUser()
    expect(mocks.api.addAppLdapUser).toHaveBeenCalledWith('orders', 'corp', 'alice')

    state.trustSourceAppId.value = ' portal '
    await state.addTrust()
    expect(mocks.api.addExchangeTrust).toHaveBeenCalledWith('orders', 'portal')

    await state.revokeSmsUser('sms-1')
    await state.revokeLdapUser('ldap-1')
    await state.revokeWechatUser('wechat-1')
    await state.restoreWechatUser('wechat-1')
    await state.removeTrust({ sourceAppId: 'portal' } as never)
    expect(mocks.api.revokeAppSmsUser).toHaveBeenCalledWith('orders', 'sms-1')
    expect(mocks.api.revokeAppLdapUser).toHaveBeenCalledWith('orders', 'ldap-1')
    expect(mocks.api.revokeAppWechatUser).toHaveBeenCalledWith('orders', 'wechat-1')
    expect(mocks.api.restoreAppWechatUser).toHaveBeenCalledWith('orders', 'wechat-1')
    expect(mocks.api.removeExchangeTrust).toHaveBeenCalledWith('orders', 'portal')

    state.clearAccess()
    expect(state.appTrusts.value).toEqual([])
  })

  it('rejects invalid access input and respects cancelled confirmations', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppAccess(selected)
    state.accessForm.phone = 'not-a-phone'
    await state.addSmsUser()
    expect(mocks.notify).toHaveBeenCalledWith('请输入有效手机号')

    mocks.confirm.mockRejectedValueOnce('cancel')
    await state.revokeSmsUser('sms-1')
    expect(mocks.api.revokeAppSmsUser).not.toHaveBeenCalled()
  })
})

describe('admin user directory', () => {
  it('loads, filters and creates password and phone accounts', async () => {
    const state = useAdminUsers()
    const active = user()
    const disabled = user({ userId: 'user-2', username: 'bob', isActive: false })
    mocks.api.getUsers.mockResolvedValue({ items: [active, disabled], total: 2, page: 1, pageSize: 12 })

    await state.loadUsers()
    state.userFilters.status = 'disabled'
    expect(state.filteredUsers.value).toEqual([disabled])

    state.createUserForm.username = ' alice '
    state.createUserForm.password = 'password123'
    state.createUserForm.nickname = ' A '
    await state.saveUser()
    expect(mocks.api.createUser).toHaveBeenCalledWith({
      username: 'alice',
      password: 'password123',
      displayName: undefined,
      nickname: 'A',
      remark: undefined,
    })

    state.userMode.value = 'phone'
    state.createUserForm.phone = '13800138000'
    await state.saveUser()
    expect(mocks.api.createPhoneUser).toHaveBeenCalledWith({
      phone: '13800138000',
      displayName: undefined,
      nickname: undefined,
      remark: undefined,
    })
  })

  it('opens history, updates metadata and changes account status', async () => {
    const state = useAdminUsers()
    const selected = user()
    mocks.api.getUserLoginHistory.mockResolvedValue({
      items: [{ eventType: 'Success' }],
      total: 1,
      page: 1,
      pageSize: 10,
    })
    state.openUser(selected)
    await nextTick()
    expect(state.userHistoryTotal.value).toBe(1)
    state.userMeta.nickname = 'Alice A'
    state.userMeta.remark = 'reviewed'
    await state.updateUserMeta('nickname')
    await state.updateUserMeta('remark')
    expect(mocks.api.updateUserNickname).toHaveBeenCalledWith('user-1', 'Alice A')
    expect(mocks.api.updateUserRemark).toHaveBeenCalledWith('user-1', 'reviewed')

    await state.toggleUser(selected)
    expect(mocks.api.updateUserStatus).toHaveBeenCalledWith('user-1', false)
    state.closeUserDrawer()
    expect(state.selectedUser.value).toBeNull()
  })
})

describe('admin security and runtime settings', () => {
  it('queries audit logs and revokes refresh tokens', async () => {
    const state = useAdminSecurity()
    state.auditFilters.action = ' UserDisabled '
    state.auditFilters.targetType = 'User'
    state.auditFilters.targetId = 'user-1'
    mocks.api.getAuditLogs.mockResolvedValue({ items: [{ action: 'UserDisabled' }], total: 1, page: 1, pageSize: 15 })
    await state.loadAuditLogs()
    expect(mocks.api.getAuditLogs).toHaveBeenCalledWith({
      action: 'UserDisabled',
      targetType: 'User',
      targetId: 'user-1',
      page: 1,
      pageSize: 15,
    })

    await state.revokeToken()
    expect(mocks.notify).toHaveBeenCalledWith('请输入完整 refresh token')
    state.tokenValue.value = ' refresh-token '
    await state.revokeToken()
    expect(mocks.api.revokeRefreshToken).toHaveBeenCalledWith('refresh-token')
    expect(state.tokenModalOpen.value).toBe(false)
  })

  it('loads and saves settings, including guarded bootstrap changes', async () => {
    const state = useAdminSettings()
    const audience: AdminSetting = {
      key: 'Jwt:Audience', valueType: 'String', isSecret: false, value: 'Services',
      hasValue: true, restartRequired: true, updatedAt: null, updatedBy: null,
    }
    const secret: AdminSetting = {
      key: 'WeChat:AppSecret', valueType: 'String', isSecret: true, value: null,
      hasValue: true, restartRequired: false, updatedAt: null, updatedBy: null,
    }
    const adminOrigin: AdminSetting = {
      key: 'AdminWeb:AllowedOrigins', valueType: 'Json', isSecret: false, value: '[]',
      hasValue: true, restartRequired: true, updatedAt: null, updatedBy: null,
    }
    mocks.api.getSettings.mockResolvedValue({
      configurationVersion: 2, runningConfigurationVersion: 1, restartPending: true, items: [audience, secret, adminOrigin],
    })
    await state.loadSettings()
    expect(state.settingGroups.value.map((group) => group.name)).toEqual(['Jwt', 'WeChat', 'AdminWeb'])
    expect(state.getSettingsForSection('settings-identity').map((setting) => setting.key)).toEqual(['Jwt:Audience'])
    expect(state.getSettingsForSection('settings-admin').map((setting) => setting.key)).toEqual(['AdminWeb:AllowedOrigins'])
    expect(state.formatValue(secret)).toBe('已配置（不会回显）')
    state.settingsDraft['Jwt:Audience'] = 'Orders'
    state.settingsDraft['WeChat:AppSecret'] = 'new-secret'
    mocks.api.updateSettings.mockResolvedValue({ restartRequired: true, message: 'saved' })
    await state.saveSettings(['Jwt:Audience'])
    expect(mocks.api.updateSettings).toHaveBeenCalledWith({ 'Jwt:Audience': 'Orders' })
    expect(state.settingsDraft['WeChat:AppSecret']).toBe('new-secret')
    expect(state.changedSettings.value.map((setting) => setting.key)).toEqual(['WeChat:AppSecret'])

    mocks.api.getBootstrapSettings.mockResolvedValue({
      provider: 'PostgreSQL', serverVersion: '15', endpoint: 'db', filePath: 'file',
      masterKeyConfigured: true, editable: true, singleInstanceOnly: false,
      scopeNotice: 'restart', supportedProviders: [],
    })
    await state.loadBootstrap()
    expect(state.hasBootstrapForm.value).toBe(true)
    await state.testBootstrapSettings()
    expect(mocks.notify).toHaveBeenCalledWith('测试前请确认你理解数据库目标切换影响')
    state.bootstrapForm.confirm = true
    mocks.api.testBootstrapSettings.mockResolvedValue({ message: 'ok', endpoint: 'db' })
    await state.testBootstrapSettings()
    expect(state.bootstrapMessage.value).toBe('ok 目标：db')
    mocks.api.updateBootstrapSettings.mockResolvedValue({ message: 'saved' })
    await state.saveBootstrapSettings()
    expect(mocks.api.updateBootstrapSettings).toHaveBeenCalled()
  })
})

describe('interactive OIDC client configuration', () => {
  function axiosRejection(status: number, message: string) {
    return {
      isAxiosError: true,
      response: { status, data: { message } },
      message: 'Request failed',
    }
  }

  it('shows an application that predates interactive configuration as not enabled', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)

    await state.loadOidc('orders')

    expect(mocks.api.getAppOidc).toHaveBeenCalledWith('orders')
    expect(state.oidcConfig.value.clientType).toBe('Confidential')
    expect(state.oidcConfig.value.allowAuthorizationCode).toBe(false)
    expect(state.oidcConfig.value.redirectUris).toEqual([])
    expect(state.oidcConfig.value.postLogoutRedirectUris).toEqual([])
    expect(state.isPublicClient.value).toBe(false)
    expect(state.oidcError.value).toBe('')
  })

  it('reflects the reloaded configuration after enabling the code flow', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)
    mocks.api.getAppOidc.mockResolvedValueOnce(oidc({
      redirectUris: [{ id: 'reg-1', kind: 'Redirect', uri: 'https://bff.example.test/signin-oidc' }],
    }))
    await state.loadOidc('orders')

    mocks.api.getAppOidc.mockResolvedValueOnce(oidc({
      allowAuthorizationCode: true,
      allowedScopes: ['openid', 'profile'],
      redirectUris: [{ id: 'reg-1', kind: 'Redirect', uri: 'https://bff.example.test/signin-oidc' }],
    }))
    state.oidcPolicyForm.allowAuthorizationCode = true
    state.oidcPolicyForm.allowedScopes = 'openid profile'
    state.oidcPolicyForm.identitySessionMaxAgeSeconds = 3600
    await state.saveOidcPolicy()

    expect(mocks.api.updateOidcPolicy).toHaveBeenCalledWith('orders', {
      clientType: 'Confidential',
      allowAuthorizationCode: true,
      allowedScopes: ['openid', 'profile'],
      allowRefreshToken: false,
      identitySessionMaxAgeSeconds: 3600,
    })
    expect(state.oidcConfig.value.allowAuthorizationCode).toBe(true)
    expect(state.oidcPolicyForm.allowedScopes).toBe('openid profile')
  })

  it('shows the rejection message verbatim and returns to the state before the save', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)
    await state.loadOidc('orders')
    const rejection = 'Enabling the authorization code flow requires at least one redirect URI.'
    mocks.api.updateOidcPolicy.mockRejectedValueOnce(axiosRejection(400, rejection))

    state.oidcPolicyForm.allowAuthorizationCode = true
    await state.saveOidcPolicy()

    expect(state.oidcError.value).toBe(rejection)
    expect(state.oidcPolicyForm.allowAuthorizationCode).toBe(false)
    expect(state.oidcConfig.value.allowAuthorizationCode).toBe(false)
  })

  it('submits each kind under its own registration and deletes by registration id', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)
    await state.loadOidc('orders')

    state.redirectUriDraft.value = '  https://BFF.example.test:8443/Signin-Oidc/  '
    await state.addRedirectUri('Redirect')
    state.postLogoutUriDraft.value = 'https://bff.example.test/signout'
    await state.addRedirectUri('PostLogout')

    // 除首尾空白外逐字符原样提交：不补尾斜杠、不小写化、不补默认端口。
    expect(mocks.api.addOidcRedirectUris).toHaveBeenNthCalledWith(1, 'orders', 'Redirect', [
      'https://BFF.example.test:8443/Signin-Oidc/',
    ])
    expect(mocks.api.addOidcRedirectUris).toHaveBeenNthCalledWith(2, 'orders', 'PostLogout', [
      'https://bff.example.test/signout',
    ])
    expect(state.redirectUriDraft.value).toBe('')
    expect(state.postLogoutUriDraft.value).toBe('')

    await state.removeRedirectUri({ id: 'reg-1', kind: 'Redirect', uri: 'https://bff.example.test/signin-oidc' })
    expect(mocks.api.removeOidcRedirectUri).toHaveBeenCalledWith('orders', 'reg-1')
  })

  it('never writes between the claims callback and the redirect registrations', async () => {
    const state = useAdminApps()
    const selected = app({ callbackUrl: 'https://claims.example.test/permissions' })
    mocks.api.getApps.mockResolvedValue([selected])
    mocks.api.getAppOidc.mockResolvedValue(oidc({
      redirectUris: [{ id: 'reg-1', kind: 'Redirect', uri: 'https://bff.example.test/signin-oidc' }],
    }))

    await state.openApp(selected)
    await nextTick()

    // 抽屉里的两份表单各自独立：任何一侧的值都不会预填到另一侧。
    expect(state.appConfig.callbackUrl).toBe('https://claims.example.test/permissions')
    expect(state.redirectUriDraft.value).toBe('')
    expect(state.oidcConfig.value.redirectUris[0].uri).toBe('https://bff.example.test/signin-oidc')

    state.redirectUriDraft.value = 'https://bff.example.test/second'
    await state.addRedirectUri('Redirect')
    expect(mocks.api.updateCallback).not.toHaveBeenCalled()
    expect(state.appConfig.callbackUrl).toBe('https://claims.example.test/permissions')

    state.appConfig.callbackUrl = 'https://claims.example.test/changed'
    await state.saveAppConfig()
    expect(mocks.api.addOidcRedirectUris).toHaveBeenCalledTimes(1)
    expect(mocks.api.updateOidcPolicy).not.toHaveBeenCalled()
  })

  it('keeps a public client fail closed and never submits it', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)
    mocks.api.getAppOidc.mockResolvedValueOnce(oidc({ clientType: 'Public' }))

    await state.loadOidc('orders')
    expect(state.isPublicClient.value).toBe(true)

    state.oidcPolicyForm.allowAuthorizationCode = true
    await state.saveOidcPolicy()

    expect(mocks.api.updateOidcPolicy).not.toHaveBeenCalled()
    expect(mocks.notify).toHaveBeenCalledWith(
      'Public 客户端保持保留状态，当前无法从控制台启用。',
    )
  })

  it('drops uncommitted edits when the administrator cancels', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)
    mocks.api.getAppOidc.mockResolvedValueOnce(oidc({
      allowAuthorizationCode: true,
      allowedScopes: ['openid'],
      allowRefreshToken: true,
      identitySessionMaxAgeSeconds: 1800,
    }))
    await state.loadOidc('orders')

    state.oidcPolicyForm.allowAuthorizationCode = false
    state.oidcPolicyForm.allowedScopes = 'openid profile email'
    state.oidcPolicyForm.allowRefreshToken = false
    state.oidcPolicyForm.identitySessionMaxAgeSeconds = 60
    state.redirectUriDraft.value = 'https://bff.example.test/unsubmitted'
    state.resetPolicyForm()

    expect(state.oidcPolicyForm.allowAuthorizationCode).toBe(true)
    expect(state.oidcPolicyForm.allowedScopes).toBe('openid')
    expect(state.oidcPolicyForm.allowRefreshToken).toBe(true)
    expect(state.oidcPolicyForm.identitySessionMaxAgeSeconds).toBe(1800)
    expect(state.redirectUriDraft.value).toBe('')
    expect(mocks.api.updateOidcPolicy).not.toHaveBeenCalled()
  })

  it('routes an expired session through the shared unauthorized handler', async () => {
    const selected = ref<AdminApp | null>(app())
    const state = useAdminAppOidc(selected)
    mocks.api.getAppOidc.mockRejectedValueOnce(axiosRejection(401, 'Unauthorized'))

    await state.loadOidc('orders')

    expect(mocks.handleApiError).toHaveBeenCalledWith(
      '加载交互式 OIDC 配置失败',
      expect.objectContaining({ isAxiosError: true }),
    )
  })
})
