import axios, { type AxiosInstance } from 'axios'

export interface PagedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

export interface AdminUser {
  userId: string
  username: string
  phone: string
  isActive: boolean
  remark: string
  nickname: string | null
  createdAt: number
  displayName: string
  hasPassword: boolean
}

export interface AdminApp {
  appId: string
  appName: string
  callbackUrl: string
  callbackExpiresAt: number | null
  isActive: boolean
  createdAt: number
  ldapLoginMode: 'Disabled' | 'ManualApproval' | 'AutoProvision'
  smsLoginMode: 'Disabled' | 'ManualApproval' | 'AutoProvision'
  smsProfileKey: string | null
  wechatLoginMode: 'Disabled' | 'BindRequired' | 'AutoProvision'
  audienceMode: 'Shared' | 'PerApplication'
  /** 当前生效的 aud 值，由后端按 audienceMode 算好 */
  audience: string
}

/** 一条 Redirect URI 注册。id 是删除时使用的 registrationId。 */
export interface AdminAppRedirectUri {
  id: string
  kind: 'Redirect' | 'PostLogout'
  uri: string
}

/**
 * 应用的交互式 OIDC 配置。
 *
 * 这里的 Redirect URI 与 AdminApp.callbackUrl（服务端到服务端的 claims callback）是两套互不相干的
 * 注册，任何一侧都不会被写入另一侧。
 */
export interface AdminAppOidc {
  appId: string
  clientType: 'Confidential' | 'Public'
  allowAuthorizationCode: boolean
  allowedScopes: string[]
  allowRefreshToken: boolean
  identitySessionMaxAgeSeconds: number | null
  audienceMode: AdminApp['audienceMode']
  redirectUris: AdminAppRedirectUri[]
  postLogoutRedirectUris: AdminAppRedirectUri[]
}

/** 整体替换交互式策略字段；audienceMode 有自己的端点，不在其中。 */
export interface AdminUpdateOidcPolicyRequest {
  clientType: AdminAppOidc['clientType']
  allowAuthorizationCode: boolean
  allowedScopes: string[]
  allowRefreshToken: boolean
  identitySessionMaxAgeSeconds: number | null
}

export interface AdminLdapUser {
  credentialId: string
  userId: string
  username: string
  samAccountName: string
  directoryKey: string
  approvalSource: 'Admin' | 'AutoProvision' | 'ExchangeGranted'
  isActive: boolean
  createdAt: number
}

export interface AdminLdapDirectory {
  key: string
  isDefault: boolean
}

export interface AdminSmsProfile {
  key: string
  provider: 'AlibabaCloud' | 'TencentCloud' | 'Logging'
}

export interface AdminSmsUser {
  loginId: string
  userId: string
  phone: string
  approvalSource: 'Admin' | 'AutoProvision' | 'ExchangeGranted'
  isActive: boolean
  createdAt: number
}

/** openId 是掩码值：后端从不返回原始 OpenId。 */
export interface AdminWechatUser {
  loginId: string
  userId: string
  openId: string
  approvalSource: 'SelfBind' | 'AutoProvision' | 'ExchangeGranted'
  isActive: boolean
  createdAt: number
}

/** 一条有向信任边：本应用接受 sourceAppId 签发的 refresh token，反向不成立。 */
export interface AdminExchangeTrust {
  sourceAppId: string
  sourceAppName: string
  sourceIsActive: boolean
  createdAt: number
}

export interface AdminCreateUserRequest {
  username: string
  password: string
  displayName?: string
  remark?: string
  nickname?: string
}

export interface AdminCreatePhoneUserRequest {
  phone: string
  displayName?: string
  remark?: string
  nickname?: string
}

export interface AdminCreateAppRequest {
  appName: string
  callbackUrl?: string
  ttlSeconds: number
}

export interface AdminUpdateCallbackRequest {
  callbackUrl?: string
  ttlSeconds: number
  isActive: boolean
}

export interface AdminSession {
  accountId: string
  username: string
  isAuthenticated: boolean
}

export interface AdminLoginHistoryItem {
  authMethod: string
  eventType: string
  clientIp: string
  userAgent: string
  failureReason: string | null
  appId: string | null
  createdAt: number
}

export interface AdminAuditLogItem {
  action: string
  targetType: string
  targetId: string
  actorId: string | null
  actorName: string | null
  description: string | null
  clientIp: string | null
  correlationId: string | null
  createdAt: number
}

class AdminApiClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      timeout: 15000,
      withCredentials: true,
    })
  }

  async login(payload: { username: string; password: string; rememberMe: boolean }) {
    const response = await this.client.post<AdminSession>('/api/admin/session/login', payload)
    return response.data
  }

  async getCurrentSession() {
    const response = await this.client.get<AdminSession>('/api/admin/session/me')
    return response.data
  }

  async logout() {
    await this.client.post('/api/admin/session/logout')
  }

  async getUsers(params: { username?: string; phone?: string; page?: number; pageSize?: number }) {
    const response = await this.client.get<PagedResponse<AdminUser>>('/api/admin/users', { params })
    return response.data
  }

  async createUser(payload: AdminCreateUserRequest) {
    const response = await this.client.post<AdminUser>('/api/admin/users', payload)
    return response.data
  }

  async createPhoneUser(payload: AdminCreatePhoneUserRequest) {
    const response = await this.client.post<AdminUser>('/api/admin/users/phone', payload)
    return response.data
  }

  async updateUserRemark(userId: string, remark: string) {
    await this.client.patch(`/api/admin/users/${userId}/remark`, { remark })
  }

  async updateUserNickname(userId: string, nickname: string) {
    await this.client.patch(`/api/admin/users/${userId}/nickname`, { nickname })
  }

  async updateUserStatus(userId: string, isActive: boolean) {
    await this.client.patch(`/api/admin/users/${userId}/status`, { isActive })
  }

  async getUserLoginHistory(userId: string, params: { page?: number; pageSize?: number } = {}) {
    const response = await this.client.get<PagedResponse<AdminLoginHistoryItem>>(
      `/api/admin/users/${userId}/login-history`, { params })
    return response.data
  }

  async getApps() {
    const response = await this.client.get<AdminApp[]>('/api/admin/apps')
    return response.data
  }

  async createApp(payload: AdminCreateAppRequest) {
    const response = await this.client.post<{
      appId: string
      appSecret: string
      appName: string
      callbackUrl: string
      callbackExpiresAt: number | null
    }>('/api/admin/apps', payload)
    return response.data
  }

  async updateCallback(appId: string, payload: AdminUpdateCallbackRequest) {
    await this.client.put(`/api/admin/apps/${appId}/callback`, payload)
  }

  async updateLdapPolicy(appId: string, mode: AdminApp['ldapLoginMode']) {
    await this.client.put(`/api/admin/apps/${appId}/ldap-policy`, { mode })
  }

  async updateSmsPolicy(appId: string, mode: AdminApp['smsLoginMode'], profileKey: string | null) {
    await this.client.put(`/api/admin/apps/${appId}/sms-policy`, { mode, profileKey })
  }

  async getSmsProfiles() {
    const response = await this.client.get<AdminSmsProfile[]>('/api/admin/sms/profiles')
    return response.data
  }

  async getAppSmsUsers(appId: string) {
    const response = await this.client.get<AdminSmsUser[]>(`/api/admin/apps/${appId}/sms-users`)
    return response.data
  }

  async addAppSmsUser(appId: string, phone: string) {
    const response = await this.client.post<AdminSmsUser>(`/api/admin/apps/${appId}/sms-users`, { phone })
    return response.data
  }

  async revokeAppSmsUser(appId: string, loginId: string) {
    await this.client.delete(`/api/admin/apps/${appId}/sms-users/${loginId}`)
  }

  async updateWechatPolicy(appId: string, mode: AdminApp['wechatLoginMode']) {
    await this.client.put(`/api/admin/apps/${appId}/wechat-policy`, { mode })
  }

  async updateAudienceMode(appId: string, mode: AdminApp['audienceMode']) {
    await this.client.put(`/api/admin/apps/${appId}/audience-mode`, { mode })
  }

  /** 交互式 OIDC 配置：未配置过的应用返回 Confidential、未启用授权码、空 URI 集合。 */
  async getAppOidc(appId: string) {
    const response = await this.client.get<AdminAppOidc>(`/api/admin/apps/${appId}/oidc`)
    return response.data
  }

  async updateOidcPolicy(appId: string, payload: AdminUpdateOidcPolicyRequest) {
    await this.client.put(`/api/admin/apps/${appId}/oidc-policy`, payload)
  }

  /** 一次提交按 kind 归属的一组 URI：全部注册成功，或者一个都不注册。 */
  async addOidcRedirectUris(appId: string, kind: AdminAppRedirectUri['kind'], uris: string[]) {
    await this.client.post(`/api/admin/apps/${appId}/oidc/redirect-uris`, { kind, uris })
  }

  async removeOidcRedirectUri(appId: string, registrationId: string) {
    await this.client.delete(`/api/admin/apps/${appId}/oidc/redirect-uris/${registrationId}`)
  }

  async getExchangeTrusts(appId: string) {
    const response = await this.client.get<AdminExchangeTrust[]>(`/api/admin/apps/${appId}/exchange-trusts`)
    return response.data
  }

  async addExchangeTrust(appId: string, sourceAppId: string) {
    const response = await this.client.post<AdminExchangeTrust>(
      `/api/admin/apps/${appId}/exchange-trusts`, { sourceAppId })
    return response.data
  }

  async removeExchangeTrust(appId: string, sourceAppId: string) {
    await this.client.delete(`/api/admin/apps/${appId}/exchange-trusts/${sourceAppId}`)
  }

  async getAppWechatUsers(appId: string) {
    const response = await this.client.get<AdminWechatUser[]>(`/api/admin/apps/${appId}/wechat-users`)
    return response.data
  }

  async revokeAppWechatUser(appId: string, loginId: string) {
    await this.client.delete(`/api/admin/apps/${appId}/wechat-users/${loginId}`)
  }

  /** 用户自助重新绑定不会清除撤销状态，恢复只能由管理员发起。 */
  async restoreAppWechatUser(appId: string, loginId: string) {
    await this.client.post(`/api/admin/apps/${appId}/wechat-users/${loginId}/restore`)
  }

  async getLdapDirectories() {
    const response = await this.client.get<AdminLdapDirectory[]>('/api/admin/ldap/directories')
    return response.data
  }

  async getAppLdapUsers(appId: string) {
    const response = await this.client.get<AdminLdapUser[]>(`/api/admin/apps/${appId}/ldap-users`)
    return response.data
  }

  async addAppLdapUser(appId: string, directoryKey: string, username: string) {
    const response = await this.client.post<AdminLdapUser>(`/api/admin/apps/${appId}/ldap-users`, {
      directoryKey,
      username,
    })
    return response.data
  }

  async revokeAppLdapUser(appId: string, credentialId: string) {
    await this.client.delete(`/api/admin/apps/${appId}/ldap-users/${credentialId}`)
  }

  async deleteApp(appId: string) {
    await this.client.delete(`/api/admin/apps/${appId}`)
  }

  async resetAppSecret(appId: string) {
    const response = await this.client.post<{
      appId: string
      appSecret: string
      appName: string
      callbackUrl: string
      callbackExpiresAt: number | null
    }>(`/api/admin/apps/${appId}/reset-secret`)
    return response.data
  }

  async revokeRefreshToken(refreshToken: string) {
    await this.client.post('/api/admin/tokens/revoke', { refreshToken })
  }

  async getAuditLogs(params: {
    action?: string
    targetType?: string
    targetId?: string
    actorId?: string
    page?: number
    pageSize?: number
  } = {}) {
    const response = await this.client.get<PagedResponse<AdminAuditLogItem>>(
      '/api/admin/audit-logs', { params })
    return response.data
  }

  async getSettings() {
    const response = await this.client.get<AdminSettingsList>('/api/admin/settings')
    return response.data
  }

  /** Only the supplied keys change; omitting a secret leaves it untouched. */
  async updateSettings(values: Record<string, string>) {
    const response = await this.client.put<AdminSettingsUpdateResult>(
      '/api/admin/settings',
      { values },
    )
    return response.data
  }

  async getBootstrapSettings() {
    const response = await this.client.get<BootstrapSettings>('/api/admin/bootstrap')
    return response.data
  }

  async testBootstrapSettings(payload: UpdateBootstrapPayload) {
    const response = await this.client.post<BootstrapInspection>('/api/admin/bootstrap/test', payload)
    return response.data
  }

  async updateBootstrapSettings(payload: UpdateBootstrapPayload) {
    const response = await this.client.put<{ status: string; message: string }>(
      '/api/admin/bootstrap',
      payload,
    )
    return response.data
  }
}

export interface BootstrapProvider {
  provider: string
  serverVersions: string[]
  defaultPort: number | null
  singleInstanceOnly: boolean
}

export interface BootstrapSettings {
  provider: string
  serverVersion: string | null
  endpoint: string
  filePath: string
  masterKeyConfigured: boolean
  editable: boolean
  singleInstanceOnly: boolean
  scopeNotice: string
  supportedProviders: BootstrapProvider[]
}

export interface BootstrapDatabasePayload {
  provider: string
  serverVersion: string | null
  host?: string
  port?: number | null
  database?: string
  username?: string
  password?: string
  filePath?: string
  connectionString?: string
}

export interface UpdateBootstrapPayload {
  database: BootstrapDatabasePayload
  masterKey: string | null
  confirm: boolean
}

export interface BootstrapInspection {
  target: string
  endpoint: string
  canConnect: boolean
  hasProtectedData: boolean
  masterKey: string
  installationId: string | null
  message: string
}

export interface AdminSetting {
  key: string
  valueType: 'String' | 'Number' | 'Boolean' | 'Json'
  isSecret: boolean
  /** null for secrets: secret values never leave the service. */
  value: string | null
  hasValue: boolean
  restartRequired: boolean
  updatedAt: number | null
  updatedBy: string | null
}

export interface AdminSettingsList {
  configurationVersion: number
  runningConfigurationVersion: number
  restartPending: boolean
  items: AdminSetting[]
}

export interface AdminSettingsUpdateResult {
  configurationVersion: number
  changedKeys: string[]
  restartRequired: boolean
  message: string
}

export function createAdminApiClient() {
  return new AdminApiClient()
}

export function getErrorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { message?: string } | undefined
    if (data?.message) {
      return data.message
    }
    if (error.response?.status === 401) {
      return '登录状态无效，请重新登录。'
    }
    if (error.response?.status === 403) {
      return '当前账号没有管理后台访问权限。'
    }
    return error.message
  }

  if (error instanceof Error) {
    return error.message
  }

  return 'Unknown error occurred.'
}
