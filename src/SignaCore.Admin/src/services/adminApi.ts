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

export interface AdminLdapUser {
  credentialId: string
  userId: string
  username: string
  samAccountName: string
  directoryKey: string
  approvalSource: 'Admin' | 'AutoProvision'
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
  approvalSource: 'Admin' | 'AutoProvision'
  isActive: boolean
  createdAt: number
}

/** openId 是掩码值：后端从不返回原始 OpenId。 */
export interface AdminWechatUser {
  loginId: string
  userId: string
  openId: string
  approvalSource: 'SelfBind' | 'AutoProvision'
  isActive: boolean
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

  async getAppWechatUsers(appId: string) {
    const response = await this.client.get<AdminWechatUser[]>(`/api/admin/apps/${appId}/wechat-users`)
    return response.data
  }

  async revokeAppWechatUser(appId: string, loginId: string) {
    await this.client.delete(`/api/admin/apps/${appId}/wechat-users/${loginId}`)
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
