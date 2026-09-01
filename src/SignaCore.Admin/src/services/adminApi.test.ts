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

import { createAdminApiClient, getErrorMessage } from './adminApi'

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

  it('reads settings from the authenticated settings endpoint', async () => {
    const payload = {
      configurationVersion: 2,
      runningConfigurationVersion: 1,
      restartPending: true,
      items: [],
    }
    mocks.http.get.mockResolvedValue({ data: payload })

    const result = await createAdminApiClient().getSettings()

    expect(mocks.http.get).toHaveBeenCalledWith('/api/admin/settings')
    expect(result).toBe(payload)
  })

  it('sends only the supplied settings keys', async () => {
    mocks.http.put.mockResolvedValue({ data: { changedKeys: ['Jwt:Audience'] } })

    await createAdminApiClient().updateSettings({ 'Jwt:Audience': 'Orders' })

    expect(mocks.http.put).toHaveBeenCalledWith('/api/admin/settings', {
      values: { 'Jwt:Audience': 'Orders' },
    })
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

  it('keeps bootstrap replacement behind the dedicated endpoint and confirmation payload', async () => {
    const payload = {
      database: {
        provider: 'SQLite',
        serverVersion: null,
        filePath: 'identity.db',
      },
      masterKey: null,
      confirm: true,
    }
    mocks.http.put.mockResolvedValue({ data: { status: 'saved', message: 'saved' } })

    await createAdminApiClient().updateBootstrapSettings(payload)

    expect(mocks.http.put).toHaveBeenCalledWith('/api/admin/bootstrap', payload)
  })
})

describe('getErrorMessage', () => {
  it('returns ordinary Error messages without exposing object internals', () => {
    expect(getErrorMessage(new Error('request failed'))).toBe('request failed')
    expect(getErrorMessage({ secret: 'do-not-render' })).toBe('Unknown error occurred.')
  })
})
