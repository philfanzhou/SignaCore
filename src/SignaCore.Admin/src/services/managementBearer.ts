export interface ManagementBearerLogin {
  tokenType: string
  accessToken: string
  expiresAtUtc: string
}

interface Credential {
  token: string
  expiresAtMs: number
  generation: number
}

let credential: Credential | null = null
let generation = 0
let expiredHandler: (() => void) | undefined

export function onCredentialExpired(handler: () => void) {
  expiredHandler = handler
}

export function currentGeneration() {
  return generation
}

export function isCurrentGeneration(value: number) {
  return generation === value
}

export function currentCredential(): Credential | null {
  if (credential && Date.now() >= credential.expiresAtMs) {
    clearCredential()
    expiredHandler?.()
  }
  return credential
}

export function clearCredential() {
  credential = null
  generation += 1
}

export function publishCredential(value: unknown): Credential {
  if (typeof value !== 'object' || value === null) {
    throw new Error('The management session response is invalid.')
  }
  const response = value as Partial<ManagementBearerLogin>
  const expiresAtMs = typeof response.expiresAtUtc === 'string'
    && /(?:Z|\+00:00)$/.test(response.expiresAtUtc)
    ? Date.parse(response.expiresAtUtc)
    : NaN
  if (response.tokenType !== 'Bearer'
    || typeof response.accessToken !== 'string'
    || !/^scm1\.[A-Za-z0-9_-]{43}$/.test(response.accessToken)
    || !Number.isFinite(expiresAtMs)
    || expiresAtMs <= Date.now()
    || expiresAtMs > Date.now() + 16 * 60 * 1000) {
    throw new Error('The management session response is invalid.')
  }

  generation += 1
  credential = { token: response.accessToken, expiresAtMs, generation }
  return credential
}

export class SupersededSessionError extends Error {
  constructor() {
    super('The management session changed while the request was in progress.')
  }
}
