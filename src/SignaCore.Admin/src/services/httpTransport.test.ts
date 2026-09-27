import axios from 'axios'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createAdminApiClient, getErrorMessage } from './adminApi'
import { credentialFreeClient } from './httpTransport'
import { clearCredential, publishCredential } from './managementBearer'

const origin = 'http://192.0.2.15:8080'
const originalBaseUrl = axios.defaults.baseURL
const originalPublicBaseUrl = credentialFreeClient.defaults.baseURL
const token = 'scm1.' + 'a'.repeat(43)
const requests: Request[] = []
const localValues = new Map<string, string>()
const sessionValues = new Map<string, string>()
const logValues: string[] = []
const indexedOpen = vi.fn()

function storage(values: Map<string, string>) {
  return {
    setItem: vi.fn((key: string, value: string) => { values.set(key, value) }),
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    removeItem: vi.fn((key: string) => { values.delete(key) }),
  }
}

beforeEach(() => {
  requests.length = 0
  logValues.length = 0
  localValues.clear()
  sessionValues.clear()
  indexedOpen.mockClear()
  clearCredential()
  axios.defaults.baseURL = origin
  credentialFreeClient.defaults.baseURL = origin
  vi.stubGlobal('window', { location: { origin, href: origin + '/admin' } })
  vi.stubGlobal('localStorage', storage(localValues))
  vi.stubGlobal('sessionStorage', storage(sessionValues))
  vi.stubGlobal('indexedDB', { open: indexedOpen })
  for (const level of ['log', 'warn', 'error'] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      logValues.push(JSON.stringify(args))
    })
  }
  vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
    requests.push(request)
    const path = new URL(request.url).pathname
    const body = path === '/api/admin/session/bearer/login'
      ? { tokenType: 'Bearer', accessToken: token,
          expiresAtUtc: new Date(Date.now() + 15 * 60 * 1000).toISOString() }
      : path === '/api/admin/session/me'
        ? { accountId: 'a1', username: 'admin', isAuthenticated: true }
        : { definitions: [], provider: 'SQLite' }
    return new Response(JSON.stringify(body), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    })
  }))
})

afterEach(() => {
  clearCredential()
  axios.defaults.baseURL = originalBaseUrl
  credentialFreeClient.defaults.baseURL = originalPublicBaseUrl
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('browser management transport', () => {
  it('omits same-origin Cookie for login, management, bootstrap, and health requests', async () => {
    const client = createAdminApiClient()
    await client.login({ username: 'admin', password: 'synthetic-password' })
    publishCredential({ tokenType: 'Bearer', accessToken: token,
      expiresAtUtc: new Date(Date.now() + 15 * 60 * 1000).toISOString() })
    await client.getCurrentSession()
    await client.getBootstrapSettings()
    await client.getSettingDefinitions()
    await credentialFreeClient.get('/health/live')

    expect(requests.map((request) => new URL(request.url).pathname)).toEqual([
      '/api/admin/session/bearer/login', '/api/admin/session/me', '/api/admin/bootstrap',
      '/management/v1/settings/definitions', '/health/live',
    ])
    for (const request of requests) {
      expect(request.credentials).toBe('omit')
      expect(request.redirect).toBe('manual')
      expect(request.headers.has('Cookie')).toBe(false)
    }
    expect(requests[0].headers.has('Authorization')).toBe(false)
    expect(requests.slice(1, 4).every((request) =>
      request.headers.get('Authorization') === `Bearer ${token}`)).toBe(true)
    expect(requests[4].headers.has('Authorization')).toBe(false)
  })

  it('keeps the bearer out of persistent surfaces, URL, logs, and rendered errors', async () => {
    publishCredential({ tokenType: 'Bearer', accessToken: token,
      expiresAtUtc: new Date(Date.now() + 15 * 60 * 1000).toISOString() })
    const client = createAdminApiClient()
    await client.getCurrentSession()
    const exposed = () => JSON.stringify({
      local: [...localValues.values()], session: [...sessionValues.values()],
      url: window.location.href, logs: logValues,
    })
    expect(exposed().includes(token)).toBe(false)
    expect(indexedOpen).not.toHaveBeenCalled()
    expect(getErrorMessage(new Error(token)).includes(token)).toBe(false)

    // Negative control: the scanner must detect an injected canary in storage.
    localStorage.setItem('injected', token)
    expect(exposed().includes(token)).toBe(true)
    localStorage.removeItem('injected')
  })
})
