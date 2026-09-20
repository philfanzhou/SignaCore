import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  http: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
  create: vi.fn(),
  isAxiosError: vi.fn(),
}))

vi.mock('axios', () => ({
  default: {
    create: mocks.create,
    isAxiosError: mocks.isAxiosError,
  },
}))

import {
  createAdminApiClient,
  getErrorMessage,
  parseRunningVersion,
  parseSettingsSnapshot,
} from './adminApi'

beforeEach(() => {
  vi.clearAllMocks()
  mocks.create.mockReturnValue(mocks.http)
})

describe('AdminApiClient', () => {
  it('uses one credentialed client with a bounded timeout', () => {
    createAdminApiClient()

    expect(mocks.create).toHaveBeenCalledWith({
      timeout: 15000,
      withCredentials: true,
    })
  })

  it('logs in through the shared management entry with the fixed request header', async () => {
    mocks.http.post.mockResolvedValue({ status: 204, data: '' })

    await createAdminApiClient().login({ username: 'admin', password: 'secret-value' })

    expect(mocks.http.post).toHaveBeenCalledWith('/management/v1/session/login', {
      username: 'admin',
      password: 'secret-value',
    }, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
  })

  it('reads the current session from the admin session endpoint', async () => {
    const payload = { accountId: 'account-1', username: 'admin', isAuthenticated: true }
    mocks.http.get.mockResolvedValue({ data: payload })

    const result = await createAdminApiClient().getCurrentSession()

    expect(mocks.http.get).toHaveBeenCalledWith('/api/admin/session/me')
    expect(result).toBe(payload)
  })

  it('logs out through the shared management entry with the fixed request header', async () => {
    mocks.http.post.mockResolvedValue({ status: 204, data: '' })

    await createAdminApiClient().logout()

    expect(mocks.http.post).toHaveBeenCalledWith('/management/v1/session/logout', undefined, {
      headers: { 'X-ServiceMantle-Request': '1' },
    })
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
