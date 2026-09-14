import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  login: vi.fn(),
  getCurrentSession: vi.fn(),
  logout: vi.fn(),
  isAxiosError: vi.fn(),
  loadAllDomains: vi.fn(),
  resetAllDomains: vi.fn(),
  message: {
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
  },
}))

vi.mock('axios', () => ({
  default: {
    isAxiosError: mocks.isAxiosError,
  },
}))

vi.mock('element-plus', () => ({
  ElMessage: mocks.message,
}))

vi.mock('../services/apiClient', () => ({
  adminClient: {
    login: mocks.login,
    getCurrentSession: mocks.getCurrentSession,
    logout: mocks.logout,
  },
}))

vi.mock('./sessionHooks', () => ({
  loadAllDomains: mocks.loadAllDomains,
  resetAllDomains: mocks.resetAllDomains,
}))

type UseSession = typeof import('./useSession')

let useSession: UseSession

beforeAll(async () => {
  // useSession reads the runtime-injected title from window at module scope.
  globalThis.window = { __APP_TITLE__: 'SignaCore' } as unknown as Window & typeof globalThis
  useSession = await import('./useSession')
})

function axiosError(status: number) {
  mocks.isAxiosError.mockReturnValue(true)
  return { message: 'Request failed', response: { status, data: {} } }
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.isAxiosError.mockReturnValue(false)
  useSession.resetAdminState()
  useSession.loginForm.username = ''
  useSession.loginForm.password = ''
})

describe('loginErrorMessage', () => {
  it('keeps one fixed message for every 401 rejection', () => {
    expect(useSession.loginErrorMessage(axiosError(401))).toBe('用户名或密码错误，或该账号没有管理后台权限。')
  })

  it('offers a retry hint for throttling and temporary unavailability', () => {
    expect(useSession.loginErrorMessage(axiosError(429))).toBe('登录暂时不可用，请稍后重试。')
    expect(useSession.loginErrorMessage(axiosError(503))).toBe('登录暂时不可用，请稍后重试。')
  })

  it('falls back to the shared message extraction for other failures', () => {
    expect(useSession.loginErrorMessage(new Error('network down'))).toBe('network down')
  })
})

describe('handleLogin', () => {
  it('submits only the credential pair — no remember-me flag', async () => {
    mocks.login.mockResolvedValue(undefined)
    mocks.getCurrentSession.mockResolvedValue({ accountId: 'a1', username: 'admin', isAuthenticated: true })
    useSession.loginForm.username = 'admin'
    useSession.loginForm.password = 'secret-value'

    await useSession.handleLogin()

    expect(mocks.login).toHaveBeenCalledWith({
      username: 'admin',
      password: 'secret-value',
    })
    expect('rememberMe' in useSession.loginForm).toBe(false)
    expect(mocks.getCurrentSession).toHaveBeenCalled()
    expect(mocks.loadAllDomains).toHaveBeenCalled()
    expect(mocks.message.success).toHaveBeenCalledWith('登录成功')
  })

  it('shows the fixed 401 message without echoing credentials', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.login.mockRejectedValue({ message: 'Request failed', response: { status: 401, data: {} } })
    useSession.loginForm.username = 'admin'
    useSession.loginForm.password = 'secret-value'

    await useSession.handleLogin()

    expect(mocks.message.error).toHaveBeenCalledWith(
      '登录失败: 用户名或密码错误，或该账号没有管理后台权限。',
    )
  })
})
