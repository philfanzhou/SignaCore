import axios, { type AxiosInstance } from 'axios'

export interface AdminPagedResponse<T> {
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
    const response = await this.client.get<AdminPagedResponse<AdminUser>>('/api/admin/users', { params })
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
