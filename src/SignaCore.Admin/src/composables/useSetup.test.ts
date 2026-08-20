import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  isAxiosError: vi.fn(),
}))

vi.mock('axios', () => ({
  default: {
    get: mocks.get,
    post: mocks.post,
    isAxiosError: mocks.isAxiosError,
  },
}))

import {
  probeSetupStatus,
  setupError,
  setupForm,
  setupPhase,
  submitSetup,
} from './useSetup'

beforeEach(() => {
  vi.clearAllMocks()
  setupPhase.value = 'checking'
  setupError.value = ''
  Object.assign(setupForm, {
    publicBaseUrl: 'https://identity.example.test',
    allowNonHttpsIssuer: false,
    jwtAudience: 'SignaCore.Services',
    username: 'admin',
    password: 'AdminPassword123',
    confirmPassword: 'AdminPassword123',
    setupCode: 'ABCDE-ABCDE-ABCDE-ABCDE',
  })
})

describe('setup status', () => {
  it('identifies a host that is waiting for first-run setup', async () => {
    mocks.get.mockResolvedValue({ data: { status: 'pending' } })

    expect(await probeSetupStatus()).toBe(true)
    expect(mocks.get).toHaveBeenCalledWith('/api/setup/status', { timeout: 5000 })
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

  it('trims public identifiers and reports a safe server validation error', async () => {
    setupForm.publicBaseUrl = '  https://identity.example.test  '
    setupForm.jwtAudience = '  Orders  '
    setupForm.username = '  admin  '
    setupForm.setupCode = '  ABCDE-ABCDE-ABCDE-ABCDE  '
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { data: { message: 'The setup code is invalid.' } },
    })

    await submitSetup()

    expect(mocks.post).toHaveBeenCalledWith('/api/setup/complete', {
      publicBaseUrl: 'https://identity.example.test',
      allowNonHttpsIssuer: false,
      jwtAudience: 'Orders',
      username: 'admin',
      password: 'AdminPassword123',
      confirmPassword: 'AdminPassword123',
      setupCode: 'ABCDE-ABCDE-ABCDE-ABCDE',
    })
    expect(setupError.value).toBe('The setup code is invalid.')
    expect(setupPhase.value).toBe('pending')
  })
})
