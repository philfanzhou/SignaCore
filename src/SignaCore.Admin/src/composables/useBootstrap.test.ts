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
  applyProviderDefaults,
  bootstrapAdvanced,
  bootstrapError,
  bootstrapFilePath,
  bootstrapForm,
  bootstrapMessage,
  bootstrapPhase,
  probeBootstrapStatus,
  testBootstrap,
} from './useBootstrap'

beforeEach(() => {
  vi.clearAllMocks()
  bootstrapPhase.value = 'checking'
  bootstrapError.value = ''
  bootstrapMessage.value = ''
  bootstrapFilePath.value = ''
  bootstrapAdvanced.value = false
  Object.assign(bootstrapForm, {
    provider: 'PostgreSQL',
    serverVersion: '15',
    host: '',
    port: 5432,
    database: 'signacore',
    username: 'signacore',
    password: '',
    filePath: '/app/data/signacore.db',
    connectionString: '',
    installMode: 'new',
    masterKey: '',
    bootstrapCode: '',
  })
})

describe('bootstrap status', () => {
  it('loads provider metadata and applies the selected provider defaults', async () => {
    mocks.get.mockResolvedValue({
      data: {
        status: 'required',
        filePath: '/app/config/signacore.bootstrap.json',
        supportedProviders: [
          {
            provider: 'PostgreSQL',
            serverVersions: ['17', '16', '15'],
            defaultPort: 5432,
            singleInstanceOnly: false,
          },
        ],
      },
    })

    expect(await probeBootstrapStatus()).toBe(true)
    expect(bootstrapFilePath.value).toBe('/app/config/signacore.bootstrap.json')
    expect(bootstrapForm.serverVersion).toBe('17')
    expect(bootstrapPhase.value).toBe('required')
  })

  it('falls through to the normal host when the status probe fails', async () => {
    mocks.get.mockRejectedValue(new Error('normal host'))

    expect(await probeBootstrapStatus()).toBe(false)
  })

  it('applies SQLite defaults without retaining a server port', () => {
    applyProviderDefaults({
      provider: 'SQLite',
      serverVersions: [],
      defaultPort: null,
      singleInstanceOnly: true,
    })

    expect(bootstrapForm.provider).toBe('SQLite')
    expect(bootstrapForm.serverVersion).toBe('')
    expect(bootstrapForm.port).toBeNull()
  })
})

describe('bootstrap target test', () => {
  it('sends a trimmed advanced connection and never sends a key for a new install', async () => {
    bootstrapAdvanced.value = true
    bootstrapForm.connectionString = '  Data Source=identity.db  '
    bootstrapForm.bootstrapCode = '  ABCDE  '
    bootstrapForm.installMode = 'new'
    bootstrapForm.masterKey = 'must-not-be-sent'
    mocks.post.mockResolvedValue({
      data: {
        hasProtectedData: false,
        message: 'Database is empty.',
      },
    })

    await testBootstrap()

    expect(mocks.post).toHaveBeenCalledWith('/api/bootstrap/test', {
      database: {
        provider: 'PostgreSQL',
        serverVersion: '15',
        connectionString: 'Data Source=identity.db',
      },
      installMode: 'new',
      masterKey: null,
      bootstrapCode: 'ABCDE',
    })
    expect(bootstrapMessage.value).toBe('Database is empty.')
    expect(bootstrapPhase.value).toBe('required')
  })

  it('surfaces a safe server message and returns to the editable phase', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { data: { message: 'Database target is invalid.' } },
    })

    await testBootstrap()

    expect(bootstrapError.value).toBe('Database target is invalid.')
    expect(bootstrapPhase.value).toBe('required')
  })
})
