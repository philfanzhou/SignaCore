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
  /** One-time secret of a Public → Confidential upgrade; absent on every other response. */
  issuedAppSecret?: string | null
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
  /** Omitted or 'Confidential' creates a secret-bearing client; 'Public' creates one with no secret. */
  clientType?: 'Confidential' | 'Public'
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

export interface AdminIdentitySessionItem {
  id: string
  status: string
  authMethod: string
  authTime: number
  lastSeenAt: number
  idleExpiresAt: number
  absoluteExpiresAt: number
  revokedAt: number | null
  revocationReason: string | null
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

  /**
   * 管理会话登录走共享 ServiceMantle 入口：成功返回 204 空 body，会话内容随后由
   * getCurrentSession 读取。X-ServiceMantle-Request 是共享入口的固定防跨站请求头。
   */
  async login(payload: { username: string; password: string }) {
    await this.client.post('/management/v1/session/login', payload, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
  }

  async getCurrentSession() {
    const response = await this.client.get<AdminSession>('/api/admin/session/me')
    return response.data
  }

  async logout() {
    await this.client.post('/management/v1/session/logout', undefined, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
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

  async getUserIdentitySessions(
    userId: string,
    params: { page?: number; pageSize?: number } = {},
  ) {
    const response = await this.client.get<PagedResponse<AdminIdentitySessionItem>>(
      `/api/admin/users/${userId}/identity-sessions`, { params })
    return response.data
  }

  async revokeIdentitySession(userId: string, sessionId: string) {
    const response = await this.client.post<{ success: boolean; message: string }>(
      `/api/admin/users/${userId}/identity-sessions/${sessionId}/revoke`)
    return response.data
  }

  async getApps() {
    const response = await this.client.get<AdminApp[]>('/api/admin/apps')
    return response.data
  }

  async createApp(payload: AdminCreateAppRequest) {
    const response = await this.client.post<{
      appId: string
      appSecret: string | null
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

  /**
   * 读取共享设置定义目录。定义响应不携带默认值与约束细节，只有 hasDefault。
   */
  async getSettingDefinitions() {
    const response = await this.client.get<AdminSettingDefinitions>(
      '/management/v1/settings/definitions')
    return response.data
  }

  /**
   * 读取共享聚合的当前值快照。响应体 version 是服务端 long；超出 JS 安全整数范围时以
   * null 返回，调用方必须禁止提交而不是猜测。运行版本从产品响应头解析，缺失或非法时为
   * null，表示"运行版本未知"。
   */
  async getSettings(): Promise<{
    snapshot: AdminSettingsSnapshot
    runningVersion: AdminRunningConfigurationVersion
  }> {
    const response = await this.client.get<AdminSettingsSnapshot>(
      '/management/v1/settings',
      {
        // version 必须先按文本校验再转数字：JSON.parse 会把超出安全整数范围的 long 静默
        // 舍入，舍入后的 expectedVersion 会被服务端当作另一个版本拒绝或误用。
        transformResponse: [(raw: unknown) => parseSettingsSnapshot(raw)],
      },
    )
    return {
      snapshot: response.data,
      runningVersion: parseRunningVersion(
        response.headers?.[RunningConfigurationVersionHeader],
      ),
    }
  }

  /**
   * 提交一批设置变更。changes 为空时调用方不应发起请求；expectedVersion 必须来自加载时的
   * 快照版本。成功返回提交后的新版本；409 表示版本冲突。
   */
  async updateSettings(expectedVersion: number, changes: AdminSettingChange[]) {
    const response = await this.client.post<AdminSettingsUpdateResult>(
      '/management/v1/settings',
      { expectedVersion, changes },
    )
    return response.data
  }

  async getBootstrapSettings() {
    const response = await this.client.get<BootstrapSettings>('/api/admin/bootstrap')
    return response.data
  }

  /** The probe keeps its own body shape; the guard header is the shared unsafe-request rule. */
  async testBootstrapSettings(payload: BootstrapTestPayload) {
    const response = await this.client.post<BootstrapInspection>(
      '/api/admin/bootstrap/test',
      payload,
      { headers: { 'X-ServiceMantle-Request': '1' } },
    )
    return response.data
  }

  /**
   * 管理员换库走共享更新条目：空 master key 时省略属性表示保留既有 key，确认复选框映射为
   * 固定确认 Header。成功返回 `{"restartRequired":true}`，服务随后重启。
   */
  async updateBootstrapSettings(payload: BootstrapUpdatePayload) {
    const response = await this.client.put<{ restartRequired: boolean }>(
      '/management/v1/bootstrap',
      payload,
      {
        headers: {
          'X-ServiceMantle-Request': '1',
          'X-SignaCore-Confirm-Database-Change': '1',
        },
      },
    )
    return response.data
  }
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
}

/** 试连仍使用结构化字段；后端 binder 负责组装与分类，不改变任何文件。 */
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

export interface BootstrapTestPayload {
  database: BootstrapDatabasePayload
  /** 空值表示沿用运行中的 key。 */
  masterKey: string | null
}

/** 共享 PUT 只接受完整连接串；masterKey 为空时省略属性表示保留。 */
export interface BootstrapUpdatePayload {
  database: {
    provider: string
    serverVersion: string | null
    connectionString: string
  }
  masterKey?: string
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

export interface AdminSettingDefinition {
  key: string
  valueType: AdminSettingValueType
  isRequired: boolean
  isSensitive: boolean
  hasDefault: boolean
  requiresRestart: boolean
}

export interface AdminSettingDefinitions {
  definitions: AdminSettingDefinition[]
}

export interface AdminSettingValue {
  key: string
  valueType: AdminSettingValueType
  isRequired: boolean
  isSensitive: boolean
  hasDefault: boolean
  requiresRestart: boolean
  hasValue: boolean
  source: 'missing' | 'default' | 'persisted'
  /** null for sensitive values and unset keys: neither ever leaves the service. */
  value: string | null
}

/**
 * 服务端 version 是 long。当返回值超出 JS 安全整数范围时 version 为 null：
 * 此时前端无法精确表达版本，禁止提交更新。
 */
export interface AdminSettingsSnapshot {
  version: number | null
  values: AdminSettingValue[]
}

/** null 表示移除显式值；空字符串表示"不修改"。 */
export interface AdminSettingChange {
  key: string
  value: string | null
}

export interface AdminSettingsUpdateResult {
  version: number
}

export type AdminSettingValueType = 'string' | 'number' | 'boolean' | 'json'

/** 运行版本来自产品响应头；null 表示缺失或无法解析，绝不推断为"已生效"。 */
export type AdminRunningConfigurationVersion = number | null

/** 运行版本 Header 名。CORS 已经把它加入 exposed headers。 */
export const RunningConfigurationVersionHeader = 'X-SignaCore-Running-Configuration-Version'

export function createAdminApiClient() {
  return new AdminApiClient()
}

/**
 * 解析当前值快照，并对 version 做安全整数校验。JSON.parse 会把超出
 * Number.MAX_SAFE_INTEGER 的 long 静默舍入，所以 version 以响应原文中的数字位为准：
 * 无法精确表达时返回 null，调用方据此禁止提交。
 */
export function parseSettingsSnapshot(raw: unknown): AdminSettingsSnapshot {
  const text = typeof raw === 'string' ? raw : ''
  const parsed = JSON.parse(text) as AdminSettingsSnapshot
  const match = /"version"\s*:\s*(-?\d+)/.exec(text)
  const rawVersion = match?.[1]
  const version =
    rawVersion !== undefined && Number.isSafeInteger(Number(rawVersion))
      ? Number(rawVersion)
      : null
  return { ...parsed, version }
}

/** 运行版本头缺失、非数字或超出安全整数范围时返回 null（运行版本未知）。 */
export function parseRunningVersion(raw: unknown): AdminRunningConfigurationVersion {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!/^-?\d+$/.test(trimmed)) return null
  const parsed = Number(trimmed)
  return Number.isSafeInteger(parsed) ? parsed : null
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
