import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  http: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
  publicHttp: { post: vi.fn() },
  create: vi.fn(),
  isAxiosError: vi.fn(),
  credential: { token: 'scm1.' + 'a'.repeat(43), generation: 1, expiresAtMs: Date.now() + 900000 },
}))

vi.mock('axios', () => ({
  default: {
    create: mocks.create,
    isAxiosError: mocks.isAxiosError,
  },
}))

vi.mock('./httpTransport', () => ({ credentialFreeClient: mocks.publicHttp }))
vi.mock('./managementBearer', () => ({
  currentCredential: () => mocks.credential,
  isCurrentGeneration: (value: number) => value === mocks.credential.generation,
  SupersededSessionError: class extends Error {},
}))

import {
  createAdminApiClient,
  getErrorMessage,
  parseRunningVersion,
  parseSettingDiagnostics,
  parseSettingsSnapshot,
  parseValidationErrors,
} from './adminApi'

beforeEach(() => {
  vi.clearAllMocks()
  mocks.create.mockReturnValue(mocks.http)
  vi.stubGlobal('window', { location: { origin: 'https://admin.example.test' } })
})

describe('AdminApiClient', () => {
  it('uses a cookie-free fetch client with a bounded timeout', () => {
    createAdminApiClient()

    expect(mocks.create).toHaveBeenCalledWith({
      timeout: 15000,
      adapter: 'fetch',
      withCredentials: false,
      fetchOptions: { redirect: 'manual' },
    })
  })

  it('attaches one bearer only to supported same-origin management routes', () => {
    createAdminApiClient()
    const attach = mocks.http.interceptors.request.use.mock.calls[0][0] as (config: unknown) => unknown
    function request(url: string) {
      const headers = new Map<string, string>([['Authorization', 'Bearer stale']])
      const config = {
        url,
        headers: {
          delete: (name: string) => headers.delete(name),
          set: (name: string, value: string) => headers.set(name, value),
        },
      }
      return { config, headers }
    }

    for (const route of [
      '/api/admin/session/me', '/api/admin/users', '/api/admin/bootstrap/test',
      '/management/v1/settings', '/management/v1/audit', '/management/v1/bootstrap',
    ]) {
      const { config, headers } = request(route)
      attach(config)
      expect(headers.get('Authorization')).toBe(`Bearer ${mocks.credential.token}`)
      expect((config as typeof config & { withCredentials?: boolean }).withCredentials).toBe(false)
      expect((config as typeof config & { sessionGeneration?: number }).sessionGeneration).toBe(1)
    }
    for (const route of [
      'https://outside.example.test/api/admin/users', '//outside.example.test/api/admin/users',
      '/oauth2/token', '/api/profile/me', '/api/admin/session/bearer/login',
      '/management/v1/session/logout', '/api/admin/../oauth2/token',
    ]) {
      const { config } = request(route)
      expect(() => attach(config)).toThrow('Unsupported management endpoint.')
    }
  })

  it('rejects a response from a superseded session before a domain can render it', () => {
    createAdminApiClient()
    const onResponse = mocks.http.interceptors.response.use.mock.calls[0][0] as (response: unknown) => unknown
    const old = { config: { sessionGeneration: 1 }, data: { items: ['old'] } }
    expect(onResponse(old)).toBe(old)
    mocks.credential.generation = 2
    expect(() => onResponse(old)).toThrow()
    mocks.credential.generation = 1
  })

  it('logs in through the bearer entry without attaching a prior credential', async () => {
    const issued = { tokenType: 'Bearer', accessToken: mocks.credential.token, expiresAtUtc: '2030-01-01T00:00:00Z' }
    mocks.publicHttp.post.mockResolvedValue({ status: 200, data: issued })

    const result = await createAdminApiClient().login({ username: 'admin', password: 'secret-value' })

    expect(mocks.publicHttp.post).toHaveBeenCalledWith('/api/admin/session/bearer/login', {
      username: 'admin',
      password: 'secret-value',
    }, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
    expect(result).toBe(issued)
  })

  it('reads the current session from the admin session endpoint', async () => {
    const payload = { accountId: 'account-1', username: 'admin', isAuthenticated: true }
    mocks.http.get.mockResolvedValue({ data: payload })

    const result = await createAdminApiClient().getCurrentSession()

    expect(mocks.http.get).toHaveBeenCalledWith('/api/admin/session/me')
    expect(result).toBe(payload)
  })

  it('logs out through the bearer revocation entry', async () => {
    mocks.publicHttp.post.mockResolvedValue({ status: 204, data: '' })

    await createAdminApiClient().logout(mocks.credential.token)

    expect(mocks.publicHttp.post).toHaveBeenCalledWith('/api/admin/session/bearer/logout', undefined, {
      headers: { 'X-ServiceMantle-Request': '1', Authorization: `Bearer ${mocks.credential.token}` },
    })
  })

  it('does not claim server revocation without a 204 response', async () => {
    mocks.publicHttp.post.mockResolvedValue({ status: 200, data: {} })
    await expect(createAdminApiClient().logout(mocks.credential.token))
      .rejects.toThrow('Server revocation could not be confirmed.')
  })

  it('reads settings from the shared setting query with the running-version header', async () => {
    // The mock answers with what the response transform produced (real axios would run
    // parseSettingsSnapshot on the raw body; its behavior is covered directly below).
    mocks.http.get.mockResolvedValue({
      data: { version: 2, values: [] },
      headers: { 'X-SignaCore-Running-Configuration-Version': '1' },
    })

    const { snapshot, runningVersion } = await createAdminApiClient().getSettings()

    expect(mocks.http.get).toHaveBeenCalledWith('/management/v1/settings', {
      transformResponse: [expect.any(Function)],
    })
    // The snapshot body stays the shared contract; the transform only validates the version.
    expect(snapshot).toEqual({ version: 2, values: [] })
    expect(runningVersion).toBe(1)
  })

  it('parses the snapshot version from the raw body without silent rounding', () => {
    expect(parseSettingsSnapshot('{"version":7,"values":[]}')).toEqual({
      version: 7,
      values: [],
    })
    // long.MaxValue cannot be expressed as a safe integer: refuse instead of rounding.
    expect(
      parseSettingsSnapshot('{"version":9223372036854775807,"values":[]}').version,
    ).toBeNull()
  })

  it('marks the running version unknown when the header is missing or invalid', async () => {
    mocks.http.get.mockResolvedValue({
      data: { version: 2, values: [] },
      headers: {},
    })
    await expect(createAdminApiClient().getSettings()).resolves.toEqual({
      snapshot: { version: 2, values: [] },
      runningVersion: null,
    })

    mocks.http.get.mockResolvedValue({
      data: { version: 2, values: [] },
      headers: { 'X-SignaCore-Running-Configuration-Version': 'not-a-number' },
    })
    await expect(createAdminApiClient().getSettings()).resolves.toEqual({
      snapshot: { version: 2, values: [] },
      runningVersion: null,
    })

    expect(parseRunningVersion('9007199254740993')).toBeNull()
  })

  it('reads the shared setting definitions', async () => {
    const payload = { definitions: [] }
    mocks.http.get.mockResolvedValue({ data: payload })

    const result = await createAdminApiClient().getSettingDefinitions()

    expect(mocks.http.get).toHaveBeenCalledWith('/management/v1/settings/definitions')
    expect(result).toBe(payload)
  })

  it('sends a versioned change batch to the shared update endpoint', async () => {
    mocks.http.post.mockResolvedValue({ data: { version: 3 } })

    const result = await createAdminApiClient().updateSettings(2, [
      { key: 'jwt.audience', value: 'Orders' },
      { key: 'sms.otp_hmac_key', value: null },
    ])

    expect(mocks.http.post).toHaveBeenCalledWith('/management/v1/settings', {
      expectedVersion: 2,
      changes: [
        { key: 'jwt.audience', value: 'Orders' },
        { key: 'sms.otp_hmac_key', value: null },
      ],
    })
    expect(result).toEqual({ version: 3 })
  })

  it('reads the diagnostics with safe-integer versions and closed issues', async () => {
    mocks.http.get.mockResolvedValue({
      data: {
        version: 2,
        runningVersion: 1,
        issues: [{ key: 'loki.uri', errorCode: 'signacore.setting.https_required' }],
      },
    })

    const result = await createAdminApiClient().getSettingDiagnostics()

    expect(mocks.http.get).toHaveBeenCalledWith('/management/v1/settings/diagnostics', {
      transformResponse: [expect.any(Function)],
    })
    expect(result).toEqual({
      version: 2,
      runningVersion: 1,
      issues: [{ key: 'loki.uri', errorCode: 'signacore.setting.https_required' }],
    })

    // Versions beyond the safe-integer range become null — unknown, never rounded.
    expect(parseSettingDiagnostics(
      '{"version":9223372036854775807,"runningVersion":1,"issues":[]}').version,
    ).toBeNull()
    expect(parseSettingDiagnostics(
      '{"version":2,"runningVersion":9007199254740993,"issues":[]}').runningVersion,
    ).toBeNull()

    // The issue list stays the closed shape; anything else is dropped, a null key is kept.
    const parsed = parseSettingDiagnostics(
      '{"version":2,"runningVersion":1,"issues":[' +
      '{"key":null,"errorCode":"signacore.setting.runtime_invalid"},' +
      '{"key":"loki.uri","errorCode":"signacore.setting.https_required"},' +
      '{"key":"loki.uri"},' +
      '42]}')
    expect(parsed.issues).toEqual([
      { key: null, errorCode: 'signacore.setting.runtime_invalid' },
      { key: 'loki.uri', errorCode: 'signacore.setting.https_required' },
    ])
  })

  it('parses the 400 compatibility field only when it is the closed array', () => {
    expect(parseValidationErrors({
      errorCode: 'management.request.invalid',
      validationErrors: [
        { key: 'loki.uri', errorCode: 'signacore.setting.https_required' },
        { key: null, errorCode: 'signacore.setting.runtime_invalid' },
      ],
    })).toEqual([
      { key: 'loki.uri', errorCode: 'signacore.setting.https_required' },
      { key: null, errorCode: 'signacore.setting.runtime_invalid' },
    ])

    // The generic 400 body, a non-array, or an empty list all fall back to null.
    expect(parseValidationErrors({ errorCode: 'management.request.invalid' })).toBeNull()
    expect(parseValidationErrors('management.request.invalid')).toBeNull()
    expect(parseValidationErrors({ validationErrors: 'nope' })).toBeNull()
    expect(parseValidationErrors({ validationErrors: [] })).toBeNull()
  })

  it('reads the interactive OIDC configuration of one application', async () => {
    const payload = {
      appId: 'orders',
      clientType: 'Confidential',
      allowAuthorizationCode: false,
      allowedScopes: ['openid'],
      allowRefreshToken: false,
      identitySessionMaxAgeSeconds: null,
      audienceMode: 'Shared',
      redirectUris: [],
      postLogoutRedirectUris: [],
    }
    mocks.http.get.mockResolvedValue({ data: payload })

    const result = await createAdminApiClient().getAppOidc('orders')

    expect(mocks.http.get).toHaveBeenCalledWith('/api/admin/apps/orders/oidc')
    expect(result).toBe(payload)
  })

  it('replaces the interactive policy fields in one request', async () => {
    mocks.http.put.mockResolvedValue({ data: undefined })

    await createAdminApiClient().updateOidcPolicy('orders', {
      clientType: 'Confidential',
      allowAuthorizationCode: true,
      allowedScopes: ['openid', 'profile'],
      allowRefreshToken: false,
      identitySessionMaxAgeSeconds: 3600,
    })

    expect(mocks.http.put).toHaveBeenCalledWith('/api/admin/apps/orders/oidc-policy', {
      clientType: 'Confidential',
      allowAuthorizationCode: true,
      allowedScopes: ['openid', 'profile'],
      allowRefreshToken: false,
      identitySessionMaxAgeSeconds: 3600,
    })
  })

  it('registers redirect and post logout URIs under their own kind', async () => {
    mocks.http.post.mockResolvedValue({ data: undefined })
    const client = createAdminApiClient()

    await client.addOidcRedirectUris('orders', 'Redirect', ['https://bff.example.test/signin-oidc'])
    await client.addOidcRedirectUris('orders', 'PostLogout', ['https://bff.example.test/signout'])

    expect(mocks.http.post).toHaveBeenNthCalledWith(1, '/api/admin/apps/orders/oidc/redirect-uris', {
      kind: 'Redirect',
      uris: ['https://bff.example.test/signin-oidc'],
    })
    expect(mocks.http.post).toHaveBeenNthCalledWith(2, '/api/admin/apps/orders/oidc/redirect-uris', {
      kind: 'PostLogout',
      uris: ['https://bff.example.test/signout'],
    })
  })

  it('removes one URI registration by its registration id', async () => {
    mocks.http.delete.mockResolvedValue({ data: undefined })

    await createAdminApiClient().removeOidcRedirectUri('orders', 'registration-1')

    expect(mocks.http.delete).toHaveBeenCalledWith(
      '/api/admin/apps/orders/oidc/redirect-uris/registration-1',
    )
  })

  it('keeps the probe behind its guard header and classifies without writing', async () => {
    const payload = {
      database: {
        provider: 'SQLite',
        serverVersion: null,
        filePath: 'identity.db',
      },
      masterKey: null,
    }
    mocks.http.post.mockResolvedValue({ data: { target: 'empty', endpoint: 'identity.db' } })

    await createAdminApiClient().testBootstrapSettings(payload)

    expect(mocks.http.post).toHaveBeenCalledWith('/api/admin/bootstrap/test', payload, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
  })

  it('sends the confirmed update to the shared entry and omits an empty master key', async () => {
    mocks.http.put.mockResolvedValue({ data: { restartRequired: true } })

    const result = await createAdminApiClient().updateBootstrapSettings({
      database: {
        provider: 'SQLite',
        serverVersion: null,
        connectionString: 'Data Source=identity.db',
      },
    })

    expect(mocks.http.put).toHaveBeenCalledWith('/management/v1/bootstrap', {
      database: {
        provider: 'SQLite',
        serverVersion: null,
        connectionString: 'Data Source=identity.db',
      },
    }, {
      headers: {
        'X-ServiceMantle-Request': '1',
        'X-SignaCore-Confirm-Database-Change': '1',
      },
    })
    expect(result).toEqual({ restartRequired: true })
  })
})

describe('getErrorMessage', () => {
  it('returns ordinary Error messages without exposing object internals', () => {
    expect(getErrorMessage(new Error('request failed'))).toBe('request failed')
    expect(getErrorMessage({ secret: 'do-not-render' })).toBe('Unknown error occurred.')
  })
})
