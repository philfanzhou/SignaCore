import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'
import { credentialFreeClient } from './httpTransport'
import {
  currentCredential, isCurrentGeneration, SupersededSessionError,
  type ManagementBearerLogin,
} from './managementBearer'

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

/**
 * 共享受限审计查询（GET /management/v1/audit）的一条记录。字段是共享端点的封闭投影：
 * 没有旧 audit_logs 的 before/after 快照，操作者带来源，outcome 是封闭枚举。
 */
export interface AdminAuditLogItem {
  id: string
  operator: {
    operatorId: string | null
    displayName: string | null
    source: string
  }
  action: string
  target: { type: string; id: string }
  outcome: 'unknown' | 'success' | 'failure' | 'denied'
  occurredAtUtc: string
  clientIp: string | null
  correlationId: string | null
  securityDescription: string | null
  metadata: Record<string, string>
}

/**
 * 共享审计查询的分页响应。keyset 分页：page>1 必须携带上一页返回的 continuationCursor，
 * 因此前端翻页要自己记住每页的游标；totalCount 只是展示值，不代表快照一致性。
 */
export interface AdminAuditLogPage {
  items: AdminAuditLogItem[]
  page: number
  pageSize: number
  totalCount: number
  continuationCursor: string | null
  hasNextPage: boolean
}

function managementRoute(value: string | undefined): boolean {
  if (!value?.startsWith('/') || value.startsWith('//') || value.includes('\\')) return false
  const origin = window.location.origin
  const url = new URL(value, origin)
  if (url.origin !== origin || url.hash) return false
  const path = url.pathname
  if (path === '/api/admin/session/me') return true
  if (path.startsWith('/api/admin/session/')) return false
  return path.startsWith('/api/admin/')
    || /^\/management\/v1\/(?:settings|audit|bootstrap)(?:\/|$)/.test(path)
}

class AdminApiClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      timeout: 15000,
      adapter: 'fetch',
      withCredentials: false,
      fetchOptions: { redirect: 'manual' },
    })
    this.client.interceptors.request.use((config) => {
      config.adapter = 'fetch'
      config.withCredentials = false
      config.fetchOptions = { ...config.fetchOptions, redirect: 'manual' }
      const route = managementRoute(config.url)
      if (!route) throw new Error('Unsupported management endpoint.')
      const credential = currentCredential()
      if (!credential) throw new Error('The management session has expired. Sign in again.')
      const request = config as InternalAxiosRequestConfig & { sessionGeneration?: number }
      request.sessionGeneration = credential.generation
      config.headers.delete('Authorization')
      config.headers.set('Authorization', `Bearer ${credential.token}`)
      return config
    })
    this.client.interceptors.response.use(
      (response) => {
        const request = response.config as InternalAxiosRequestConfig & { sessionGeneration?: number }
        if (!isCurrentGeneration(request.sessionGeneration ?? -1)) throw new SupersededSessionError()
        return response
      },
      (error: unknown) => {
        if (axios.isAxiosError(error)) {
          const request = error.config as (InternalAxiosRequestConfig & { sessionGeneration?: number }) | undefined
          if (request?.sessionGeneration !== undefined
            && !isCurrentGeneration(request.sessionGeneration)) throw new SupersededSessionError()
        }
        return Promise.reject(error)
      },
    )
  }

  async login(payload: { username: string; password: string }): Promise<ManagementBearerLogin> {
    const response = await credentialFreeClient.post<ManagementBearerLogin>(
      '/api/admin/session/bearer/login', payload, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
    return response.data
  }

  async getCurrentSession() {
    const response = await this.client.get<AdminSession>('/api/admin/session/me')
    return response.data
  }

  async logout(token: string) {
    const response = await credentialFreeClient.post('/api/admin/session/bearer/logout', undefined, {
      headers: { 'X-ServiceMantle-Request': '1', Authorization: `Bearer ${token}` },
    })
    if (response.status !== 204) throw new Error('Server revocation could not be confirmed.')
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
    operatorId?: string
    page?: number
    pageSize?: number
    cursor?: string
  } = {}) {
    const response = await this.client.get<AdminAuditLogPage>(
      '/management/v1/audit', { params })
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
   * 快照版本。成功返回提交后的新版本；409 表示版本冲突。确定的校验拒绝（400）由调用方从
   * axios 错误响应里用 parseValidationErrors 解析。
   */
  async updateSettings(expectedVersion: number, changes: AdminSettingChange[]) {
    const response = await this.client.post<AdminSettingsUpdateResult>(
      '/management/v1/settings',
      { expectedVersion, changes },
    )
    return response.data
  }

  /**
   * Reads the saved-version diagnostics. `version` and `runningVersion` are server longs; either
   * is null when it cannot be represented exactly, and the caller must treat that as unknown
   * instead of guessing. A failed read rejects — it is never "no issues".
   */
  async getSettingDiagnostics(): Promise<AdminSettingDiagnostics> {
    const response = await this.client.get(
      '/management/v1/settings/diagnostics',
      {
        transformResponse: [(raw: unknown) => parseSettingDiagnostics(raw)],
      },
    )
    return response.data as AdminSettingDiagnostics
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

/** null key 的固定归类：JSON null，映射时给通用英文说明。 */
export interface AdminSettingValidationError {
  key: string | null
  errorCode: string
}

export interface AdminSettingDiagnosticIssue {
  key: string | null
  errorCode: string
}

/**
 * 诊断响应：version 是本次完整保存观察到的版本，runningVersion 是本进程启动时激活的版本；
 * null 表示无法精确表达，调用方不得推断。issues 只描述该保存版本的不可用可选规则，
 * 不代表运行中的 sink。
 */
export interface AdminSettingDiagnostics {
  version: number | null
  runningVersion: number | null
  issues: AdminSettingDiagnosticIssue[]
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

/**
 * 解析诊断响应。与快照 version 同理，version/runningVersion 先按文本校验再转数字：
 * 超出安全整数范围时为 null，调用方不得把 null 当作任何版本。
 */
export function parseSettingDiagnostics(raw: unknown): AdminSettingDiagnostics {
  const text = typeof raw === 'string' ? raw : ''
  const parsed = JSON.parse(text) as AdminSettingDiagnostics
  const safeNumber = (name: string): number | null => {
    const match = new RegExp(`"${name}"\\s*:\\s*(-?\\d+)`).exec(text)
    const rawValue = match?.[1]
    return rawValue !== undefined && Number.isSafeInteger(Number(rawValue))
      ? Number(rawValue)
      : null
  }
  return {
    version: safeNumber('version'),
    runningVersion: safeNumber('runningVersion'),
    issues: Array.isArray(parsed.issues)
      ? parsed.issues
          .filter(
            (issue): issue is AdminSettingDiagnosticIssue =>
              issue !== null &&
              typeof issue === 'object' &&
              (issue.key === null || typeof issue.key === 'string') &&
              typeof issue.errorCode === 'string',
          )
          .map((issue) => ({ key: issue.key, errorCode: issue.errorCode }))
      : [],
  }
}

/**
 * 解析 400 校验拒绝里的兼容字段；不是该形状（或为空）时返回 null，调用方回落到通用
 * 错误处理。数组之外的任意字段一律忽略，键与错误码由产品闭集保证。
 */
export function parseValidationErrors(raw: unknown): AdminSettingValidationError[] | null {
  if (raw === null || typeof raw !== 'object') return null
  const candidate = raw as { validationErrors?: unknown }
  if (!Array.isArray(candidate.validationErrors)) return null
  const errors = candidate.validationErrors
    .filter(
      (error): error is AdminSettingValidationError =>
        error !== null &&
        typeof error === 'object' &&
        ((error as AdminSettingValidationError).key === null ||
          typeof (error as AdminSettingValidationError).key === 'string') &&
        typeof (error as AdminSettingValidationError).errorCode === 'string',
    )
    .map((error) => ({ key: error.key, errorCode: error.errorCode }))
  return errors.length ? errors : null
}

export function getErrorMessage(error: unknown) {
  const safe = (value: string) => value
    .replace(/(?:Bearer\s+)?scm1\.[A-Za-z0-9_-]{43}/g, '[redacted]')
    .slice(0, 500)
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { message?: string } | undefined
    if (typeof data?.message === 'string' && data.message) {
      return safe(data.message)
    }
    if (error.response?.status === 401) {
      return 'The management session is invalid. Sign in again.'
    }
    if (error.response?.status === 403) {
      return 'This account has no management access.'
    }
    return safe(error.message)
  }

  if (error instanceof Error) {
    return safe(error.message)
  }

  return 'Unknown error occurred.'
}
