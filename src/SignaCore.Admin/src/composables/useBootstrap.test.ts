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
  bootstrapForm,
  bootstrapMessage,
  bootstrapPhase,
  bootstrapProviders,
  probeBootstrapStatus,
  saveBootstrap,
  testBootstrap,
} from './useBootstrap'

const credentialHeaders = {
  'X-ServiceMantle-Request': '1',
  'X-ServiceMantle-Bootstrap-Credential': 'ABCDE',
}

beforeEach(() => {
  vi.clearAllMocks()
  bootstrapPhase.value = 'checking'
  bootstrapError.value = ''
  bootstrapMessage.value = ''
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
    bootstrapCredential: '',
  })
})

describe('bootstrap status', () => {
  it('recognizes the shared installation status entry in the bootstrap phase', async () => {
    mocks.get.mockResolvedValue({
      status: 200,
      data: {
        phase: 'bootstrap_configuration',
        migrationStatus: 'notStarted',
        databaseStatus: 'unreachable',
        bootstrapConfigured: false,
        restartRequired: false,
      },
    })

    expect(await probeBootstrapStatus()).toBe(true)
    expect(bootstrapPhase.value).toBe('required')
    expect(mocks.get).toHaveBeenCalledWith('/management/v1/status', expect.anything())
  })

  it('falls through to the normal host when the entry reports another phase or is absent', async () => {
    mocks.get.mockResolvedValue({ status: 200, data: { phase: 'pending_setup' } })
    expect(await probeBootstrapStatus()).toBe(false)

    mocks.get.mockResolvedValue({ status: 404, data: {} })
    expect(await probeBootstrapStatus()).toBe(false)

    mocks.get.mockRejectedValue(new Error('normal host'))
    expect(await probeBootstrapStatus()).toBe(false)
  })

  it('applies the fixed provider catalog and SQLite defaults without retaining a server port', () => {
    expect(bootstrapProviders.value.map(item => item.provider)).toEqual(['PostgreSQL', 'SQLite'])
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
  it('sends structured fields with the required headers and never sends a key for a new install', async () => {
    bootstrapForm.bootstrapCredential = '  ABCDE  '
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
        host: '',
        port: 5432,
        database: 'signacore',
        username: 'signacore',
        password: '',
        filePath: '/app/data/signacore.db',
      },
      masterKey: null,
    }, { headers: credentialHeaders })
    expect(bootstrapMessage.value).toBe('Database is empty.')
    expect(bootstrapPhase.value).toBe('required')
  })

  it('surfaces the fixed credential rejection on 401', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 401, data: { errorCode: 'management.bootstrap.credential_invalid' } },
    })

    await testBootstrap()

    expect(bootstrapError.value).toContain('invalid, expired, or already used')
    expect(bootstrapPhase.value).toBe('required')
  })
})

describe('bootstrap save', () => {
  it('posts a complete quoted connection string with the credential headers and omits the key for a new install', async () => {
    bootstrapForm.bootstrapCredential = '  ABCDE  '
    bootstrapForm.installMode = 'new'
    bootstrapForm.masterKey = 'must-not-be-sent'
    bootstrapForm.host = 'db'
    bootstrapForm.port = 5433
    bootstrapForm.database = 'signa;core'
    bootstrapForm.username = 'signacore'
    bootstrapForm.password = 'a;b'
    mocks.post.mockResolvedValue({ status: 201, data: { restartRequired: true } })
    vi.stubGlobal('window', { setInterval: vi.fn(), clearInterval: vi.fn(), location: { assign: vi.fn() } })

    await saveBootstrap()

    expect(mocks.post).toHaveBeenCalledWith('/management/v1/bootstrap', {
      database: {
        provider: 'PostgreSQL',
        serverVersion: '15',
        connectionString: 'Host="db";Port=5433;Database="signa;core";Username="signacore";Password="a;b"',
      },
    }, { headers: credentialHeaders })
    expect(bootstrapPhase.value).toBe('restarting')
    expect(bootstrapForm.bootstrapCredential).toBe('')
    vi.unstubAllGlobals()
  })

  it('quotes the SQLite file path so separator characters survive verbatim', async () => {
    bootstrapForm.provider = 'SQLite'
    bootstrapForm.installMode = 'new'
    bootstrapForm.filePath = "/app/a;b'c.db"
    bootstrapForm.bootstrapCredential = 'ABCDE'
    mocks.post.mockResolvedValue({ status: 201, data: { restartRequired: true } })
    vi.stubGlobal('window', { setInterval: vi.fn(), clearInterval: vi.fn(), location: { assign: vi.fn() } })

    await saveBootstrap()

    expect(mocks.post).toHaveBeenCalledWith('/management/v1/bootstrap', {
      database: {
        provider: 'SQLite',
        serverVersion: null,
        connectionString: 'Data Source="/app/a;b\'c.db"',
      },
    }, { headers: credentialHeaders })
    vi.unstubAllGlobals()
  })

  it('sends the trimmed advanced connection string and the key for an existing installation', async () => {
    bootstrapAdvanced.value = true
    bootstrapForm.connectionString = '  Host=db;Database=x  '
    bootstrapForm.installMode = 'existing'
    bootstrapForm.masterKey = ' existing-key '
    bootstrapForm.bootstrapCredential = 'ABCDE'
    mocks.post.mockResolvedValue({ status: 201, data: { restartRequired: true } })
    vi.stubGlobal('window', { setInterval: vi.fn(), clearInterval: vi.fn(), location: { assign: vi.fn() } })

    await saveBootstrap()

    expect(mocks.post).toHaveBeenCalledWith('/management/v1/bootstrap', {
      database: {
        provider: 'PostgreSQL',
        serverVersion: '15',
        connectionString: 'Host=db;Database=x',
      },
      masterKey: 'existing-key',
    }, { headers: credentialHeaders })
    vi.unstubAllGlobals()
  })

  it('maps the closed save rejections to fixed messages', async () => {
    mocks.isAxiosError.mockReturnValue(true)
    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 401, data: { errorCode: 'management.bootstrap.credential_invalid' } },
    })
    await saveBootstrap()
    expect(bootstrapError.value).toContain('invalid, expired, or already used')

    mocks.post.mockRejectedValue({
      message: 'Request failed',
      response: { status: 400, data: { errorCode: 'management.request.invalid' } },
    })
    await saveBootstrap()
    expect(bootstrapError.value).toContain('Test the database first')
    expect(bootstrapPhase.value).toBe('required')
  })
})
