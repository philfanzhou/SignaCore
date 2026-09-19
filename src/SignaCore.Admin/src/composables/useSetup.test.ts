import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  isAxiosError: vi.fn(),
  locationAssign: vi.fn(),
}))

vi.mock('axios', () => ({
  default: {
    get: mocks.get,
    post: mocks.post,
    isAxiosError: mocks.isAxiosError,
  },
}))

// The composable polls through window.* like the browser build does; the node test environment
// provides a minimal window whose timers delegate to the (fake-timer) globals.
vi.stubGlobal('window', {
  setInterval: (handler: () => void, timeout: number) => setInterval(handler, timeout),
  clearInterval: (id: ReturnType<typeof setInterval>) => clearInterval(id),
  location: { assign: mocks.locationAssign },
})

import {
  probeSetupStatus,
  setupError,
  setupForm,
  setupPhase,
  submitSetup,
} from './useSetup'

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  setupPhase.value = 'checking'
  setupError.value = ''
  Object.assign(setupForm, {
    publicBaseUrl: 'https://identity.example.test',
    allowNonHttpsIssuer: false,
    jwtAudience: 'SignaCore.Services',
    username: 'admin',
    password: 'AdminPassword123',
    confirmPassword: 'AdminPassword123',
    setupCode: 'SentinelSetupCode0123456789_-ABC',
  })
})

afterEach(() => {
  vi.useRealTimers()
})

describe('setup status', () => {
  it('probes the shared setup entry and reports a pending installation', async () => {
    mocks.get.mockResolvedValue({ data: { status: 'pending' } })

    expect(await probeSetupStatus()).toBe(true)
    expect(mocks.get).toHaveBeenCalledWith('/management/v1/setup', { timeout: 5000 })
  })

  it('falls through to login when the shared entry reports completed', async () => {
    mocks.get.mockResolvedValue({ data: { status: 'completed' } })

    expect(await probeSetupStatus()).toBe(false)
  })

  it('falls through to login when the setup endpoint is unavailable', async () => {
    mocks.get.mockRejectedValue(new Error('normal host'))

    expect(await probeSetupStatus()).toBe(false)
  })
})

describe('setup submission', () => {
  it('refuses mismatched passwords without sending either password', async () => {
    setupForm.confirmPassword = 'different'

    await submitSetup()

    expect(setupError.value).not.toBe('')
    expect(mocks.post).not.toHaveBeenCalled()
  })

  it('pre-validates a non-URL public base URL without submitting it', async () => {
    setupForm.publicBaseUrl = 'not-a-url'

    await submitSetup()

    expect(setupError.value).toContain('公开地址')
    expect(mocks.post).not.toHaveBeenCalled()
  })

  it('pre-validates an over-long username without submitting it', async () => {
    setupForm.username = 'a'.repeat(101)

    await submitSetup()

    expect(setupError.value).toContain('用户名')
    expect(mocks.post).not.toHaveBeenCalled()
  })

  it('submits the trimmed form to the shared entry with the fixed header', async () => {
    setupForm.publicBaseUrl = '  https://identity.example.test  '
    setupForm.jwtAudience = '  Orders  '
    setupForm.username = '  admin  '
    setupForm.setupCode = '  SentinelSetupCode0123456789_-ABC  '
    mocks.post.mockResolvedValue({ status: 204 })

    await submitSetup()

    expect(mocks.post).toHaveBeenCalledTimes(1)
    const [url, body, config] = mocks.post.mock.calls[0]
    expect(url).toBe('/management/v1/setup')
    // The confirmation never travels; the password is not trimmed.
    expect(body).toEqual({
      code: 'SentinelSetupCode0123456789_-ABC',
      input: {
        publicBaseUrl: 'https://identity.example.test',
        allowNonHttpsIssuer: false,
        jwtAudience: 'Orders',
        username: 'admin',
        password: 'AdminPassword123',
      },
    })
    expect(config).toEqual({ headers: { 'X-ServiceMantle-Request': '1' } })
    // The secrets are dropped as soon as the submission is accepted.
    expect(setupForm.password).toBe('')
    expect(setupForm.confirmPassword).toBe('')
    expect(setupForm.setupCode).toBe('')
    expect(setupPhase.value).toBe('restarting')
  })

  it('maps a 400 validation rejection to the fixed Chinese message', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 400, data: {} },
    })

    await submitSetup()

    expect(setupError.value).toBe(
      '提交内容未通过校验：请检查公开地址、JWT Audience、用户名长度（1-100）和密码策略',
    )
    expect(setupPhase.value).toBe('pending')
  })

  it('maps a 401 credential rejection to the fixed Chinese message', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 401, data: { errorCode: 'management.setup.credential_invalid' } },
    })

    await submitSetup()

    expect(setupError.value).toBe('初始化码无效或已过期。')
    expect(setupPhase.value).toBe('pending')
  })

  it('maps a 429 rate-limit rejection to the retry-later message', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 429, data: {} },
    })

    await submitSetup()

    expect(setupError.value).toBe('尝试次数过多，请稍后再试。')
    expect(setupPhase.value).toBe('pending')
  })

  it('maps a 503 unavailability to the retry-later message', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 503, data: { errorCode: 'management.setup.unavailable' } },
    })

    await submitSetup()

    expect(setupError.value).toBe('服务暂不可用，请稍后重试。')
    expect(setupPhase.value).toBe('pending')
  })

  it('treats a 409 conflict as a restart, not an error', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 409, data: {} },
    })

    await submitSetup()

    expect(setupError.value).toBe('')
    expect(setupPhase.value).toBe('restarting')
  })

  it('completes the restart polling once readiness returns', async () => {
    mocks.post.mockResolvedValue({ status: 204 })
    mocks.get.mockResolvedValue({ status: 200 })

    await submitSetup()

    await vi.advanceTimersByTimeAsync(2100)
    expect(setupPhase.value).toBe('completed')
    expect(mocks.locationAssign).toHaveBeenCalledWith('/admin')
  })
})
