import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { currentCredential } from '../services/managementBearer'

const mocks = vi.hoisted(() => ({
  login: vi.fn(), getCurrentSession: vi.fn(), logout: vi.fn(), isAxiosError: vi.fn(),
  loadAllDomains: vi.fn(), resetAllDomains: vi.fn(),
  message: { success: vi.fn(), error: vi.fn(), warning: vi.fn() },
}))

vi.mock('axios', () => ({ default: { isAxiosError: mocks.isAxiosError } }))
vi.mock('../services/httpTransport', () => ({ credentialFreeClient: { post: vi.fn() } }))
vi.mock('element-plus', () => ({ ElMessage: mocks.message }))
vi.mock('../services/apiClient', () => ({
  adminClient: { login: mocks.login, getCurrentSession: mocks.getCurrentSession, logout: mocks.logout },
}))
vi.mock('./sessionHooks', () => ({
  loadAllDomains: mocks.loadAllDomains, resetAllDomains: mocks.resetAllDomains,
}))

type UseSession = typeof import('./useSession')
let useSession: UseSession
const token = 'scm1.' + 'a'.repeat(43)
const issued = () => ({ tokenType: 'Bearer', accessToken: token,
  expiresAtUtc: new Date(Date.now() + 15 * 60 * 1000).toISOString() })
const axiosError = (status: number) => ({
  isAxiosError: true, message: 'Request failed', response: { status, data: {} },
})
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

beforeAll(async () => {
  vi.stubGlobal('window', { __APP_TITLE__: 'SignaCore' })
  useSession = await import('./useSession')
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  mocks.isAxiosError.mockImplementation((value: unknown) =>
    !!value && typeof value === 'object' && 'isAxiosError' in value)
  mocks.login.mockResolvedValue(issued())
  mocks.getCurrentSession.mockResolvedValue({ accountId: 'a1', username: 'admin', isAuthenticated: true })
  mocks.loadAllDomains.mockResolvedValue(undefined)
  mocks.logout.mockResolvedValue(undefined)
  useSession.resetAdminState()
  useSession.loginForm.username = ''
  useSession.loginForm.password = ''
})

afterEach(() => {
  useSession.resetAdminState()
  vi.useRealTimers()
})

async function signIn() {
  useSession.loginForm.username = 'admin'
  useSession.loginForm.password = 'synthetic-password'
  await useSession.handleLogin()
}

describe('Bearer-only management session', () => {
  it('starts without restoring a cookie or persisted token', () => {
    useSession.restoreSession()
    expect(useSession.checkingSession.value).toBe(false)
    expect(useSession.isAuthenticated.value).toBe(false)
    expect(currentCredential()).toBeNull()
    expect(mocks.getCurrentSession).not.toHaveBeenCalled()
  })

  it('publishes a validated memory credential and clears the password after submission', async () => {
    await signIn()
    expect(mocks.login).toHaveBeenCalledWith({ username: 'admin', password: 'synthetic-password' })
    expect(useSession.loginForm.password).toBe('')
    expect(currentCredential()?.token).toBe(token)
    expect(mocks.getCurrentSession).toHaveBeenCalledOnce()
    expect(mocks.loadAllDomains).toHaveBeenCalledOnce()
    expect(useSession.isAuthenticated.value).toBe(true)
  })

  it('rejects malformed issuance before publishing or requesting me', async () => {
    mocks.login.mockResolvedValue({ ...issued(), accessToken: 'invalid' })
    await signIn()
    expect(currentCredential()).toBeNull()
    expect(mocks.getCurrentSession).not.toHaveBeenCalled()
    expect(useSession.loginForm.password).toBe('')
  })

  it('expires at the server UTC boundary without refresh', async () => {
    await signIn()
    await vi.advanceTimersByTimeAsync(15 * 60 * 1000 - 1)
    expect(useSession.isAuthenticated.value).toBe(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(useSession.isAuthenticated.value).toBe(false)
    expect(currentCredential()).toBeNull()
    expect(mocks.login).toHaveBeenCalledOnce()
  })

  it('clears on 401 and keeps the session on 503', async () => {
    await signIn()
    useSession.handleApiError('load', axiosError(503))
    expect(useSession.isAuthenticated.value).toBe(true)
    useSession.handleApiError('load', axiosError(401))
    expect(useSession.isAuthenticated.value).toBe(false)
    expect(currentCredential()).toBeNull()
  })

  it('clears locally before logout and confirms revocation only after 204', async () => {
    await signIn()
    const pending = deferred<void>()
    mocks.logout.mockReturnValue(pending.promise)
    const logout = useSession.handleLogout()
    expect(useSession.isAuthenticated.value).toBe(false)
    expect(currentCredential()).toBeNull()
    expect(mocks.logout).toHaveBeenCalledWith(token)
    expect(mocks.message.success).not.toHaveBeenCalledWith('Signed out and server session revoked.')
    pending.resolve(undefined)
    await logout
    expect(mocks.message.success).toHaveBeenCalledWith('Signed out and server session revoked.')
  })

  it('reports unconfirmed revocation on network failure', async () => {
    await signIn()
    mocks.logout.mockRejectedValue(new Error('network unavailable'))
    await useSession.handleLogout()
    expect(useSession.isAuthenticated.value).toBe(false)
    expect(mocks.message.warning).toHaveBeenCalledWith(expect.stringContaining('not confirmed'))
  })

  it('ignores an old me response after local logout', async () => {
    const pending = deferred<{ accountId: string; username: string; isAuthenticated: boolean }>()
    mocks.getCurrentSession.mockReturnValueOnce(pending.promise)
    useSession.loginForm.username = 'admin'
    useSession.loginForm.password = 'synthetic-password'
    const oldLogin = useSession.handleLogin()
    await Promise.resolve()
    await Promise.resolve()
    await useSession.handleLogout()
    pending.resolve({ accountId: 'old', username: 'old', isAuthenticated: true })
    await oldLogin
    expect(useSession.isAuthenticated.value).toBe(false)
    expect(useSession.session.value).toBeNull()
    await signIn()
    expect(useSession.session.value?.accountId).toBe('a1')
  })

  it('does not publish a late credential after cancellation or a newer session', async () => {
    const pending = deferred<ReturnType<typeof issued>>()
    mocks.login.mockReturnValueOnce(pending.promise)
    useSession.loginForm.username = 'admin'
    useSession.loginForm.password = 'synthetic-password'
    const oldLogin = useSession.handleLogin()
    useSession.resetAdminState()
    pending.resolve(issued())
    await oldLogin
    expect(currentCredential()).toBeNull()
    expect(mocks.getCurrentSession).not.toHaveBeenCalled()
  })

  it('uses a fixed 401 message without echoing the password', async () => {
    mocks.login.mockRejectedValue(axiosError(401))
    await signIn()
    expect(mocks.message.error).toHaveBeenCalledWith(
      'Sign-in failed: The credentials are invalid or this account has no management access.',
    )
    expect(useSession.loginForm.password).toBe('')
  })
})
