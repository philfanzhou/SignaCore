import axios from 'axios'
import { reactive, ref } from 'vue'
import { buildPostgreSqlConnectionString, buildSqliteConnectionString } from '../utils/bootstrapConnectionString'
import {
  bootstrapProviderCatalog,
  type BootstrapProvider,
} from '../utils/bootstrapProviders'

export type BootstrapPhase = 'checking' | 'required' | 'testing' | 'saving' | 'restarting'

export type { BootstrapProvider }

interface InstallationStatus {
  phase: string
  migrationStatus: string
  databaseStatus: string
  bootstrapConfigured: boolean
  restartRequired: boolean
}

interface BootstrapInspection {
  target: string
  endpoint: string
  canConnect: boolean
  hasProtectedData: boolean
  masterKey: string
  message: string
}

const statusUrl = '/management/v1/status'
const createUrl = '/management/v1/bootstrap'
const testUrl = '/api/bootstrap/test'
const unsafeRequestHeader = 'X-ServiceMantle-Request'
const credentialHeader = 'X-ServiceMantle-Bootstrap-Credential'

export const bootstrapPhase = ref<BootstrapPhase>('checking')
export const bootstrapError = ref('')
export const bootstrapMessage = ref('')
export const bootstrapProviders = ref<BootstrapProvider[]>(bootstrapProviderCatalog)
export const bootstrapAdvanced = ref(false)

export const bootstrapForm = reactive({
  provider: 'PostgreSQL',
  serverVersion: '15',
  host: '',
  port: 5432 as number | null,
  database: 'signacore',
  username: 'signacore',
  password: '',
  filePath: '/app/data/signacore.db',
  connectionString: '',
  installMode: 'new' as 'new' | 'existing',
  masterKey: '',
  bootstrapCredential: '',
})

function messageFrom(error: unknown, fallback: string) {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { message?: string; detail?: string } | undefined
    return data?.message || data?.detail || error.message
  }
  return error instanceof Error ? error.message : fallback
}

function saveMessageFrom(status: number | undefined, error: unknown) {
  if (status === 401) {
    return 'The bootstrap credential is invalid, expired, or already used. Restart SignaCore to have a new one printed to standard output.'
  }
  if (status === 400) {
    return 'The target was refused. Test the database first; the service does not create the file for this target.'
  }
  if (status === 503) {
    return 'The service could not complete the request. Try again.'
  }
  return messageFrom(error, 'Bootstrap configuration could not be saved.')
}

export async function probeBootstrapStatus(): Promise<boolean> {
  try {
    const response = await axios.get<InstallationStatus>(statusUrl, {
      timeout: 5000,
      validateStatus: () => true,
    })
    if (response.status !== 200 || response.data.phase !== 'bootstrap_configuration') {
      return false
    }
    bootstrapPhase.value = response.data.restartRequired ? 'restarting' : 'required'
    return true
  } catch {
    return false
  }
}

export function applyProviderDefaults(provider: BootstrapProvider) {
  bootstrapForm.provider = provider.provider
  bootstrapForm.serverVersion = provider.serverVersions[0] || ''
  bootstrapForm.port = provider.defaultPort
}

// The shared creation entry accepts a complete connection string, so the structured fields are
// assembled here through the shared quoting helper: every value is double-quoted with internal
// quotes doubled, so any password character survives the provider parser verbatim. The password
// is write-only and never returned by any response. The advanced mode passes its raw string
// through unchanged.
function buildConnectionString(): string {
  if (bootstrapAdvanced.value) {
    return bootstrapForm.connectionString.trim()
  }
  if (bootstrapForm.provider === 'SQLite') {
    return buildSqliteConnectionString(bootstrapForm.filePath.trim())
  }
  return buildPostgreSqlConnectionString({
    host: bootstrapForm.host.trim(),
    port: bootstrapForm.port,
    database: bootstrapForm.database.trim(),
    username: bootstrapForm.username.trim(),
    password: bootstrapForm.password,
  })
}

function savePayload() {
  const payload: { database: object; masterKey?: string } = {
    database: {
      provider: bootstrapForm.provider,
      serverVersion: bootstrapForm.provider === 'SQLite' ? null : bootstrapForm.serverVersion || null,
      connectionString: buildConnectionString(),
    },
  }
  if (bootstrapForm.installMode === 'existing' && bootstrapForm.masterKey.trim()) {
    payload.masterKey = bootstrapForm.masterKey.trim()
  }
  return payload
}

function testPayload() {
  if (bootstrapAdvanced.value) {
    return {
      database: {
        provider: bootstrapForm.provider,
        serverVersion: bootstrapForm.provider === 'SQLite' ? null : bootstrapForm.serverVersion || null,
        connectionString: bootstrapForm.connectionString.trim(),
      },
      masterKey: bootstrapForm.installMode === 'existing' ? bootstrapForm.masterKey.trim() || null : null,
    }
  }

  return {
    database: {
      provider: bootstrapForm.provider,
      serverVersion: bootstrapForm.provider === 'SQLite' ? null : bootstrapForm.serverVersion || null,
      host: bootstrapForm.host.trim(),
      port: bootstrapForm.port,
      database: bootstrapForm.database.trim(),
      username: bootstrapForm.username.trim(),
      password: bootstrapForm.password,
      filePath: bootstrapForm.filePath.trim(),
    },
    masterKey: bootstrapForm.installMode === 'existing' ? bootstrapForm.masterKey.trim() || null : null,
  }
}

function credentialHeaders() {
  return {
    [unsafeRequestHeader]: '1',
    [credentialHeader]: bootstrapForm.bootstrapCredential.trim(),
  }
}

export async function testBootstrap() {
  bootstrapError.value = ''
  bootstrapMessage.value = ''
  bootstrapPhase.value = 'testing'
  try {
    const response = await axios.post<BootstrapInspection>(testUrl, testPayload(), {
      headers: credentialHeaders(),
    })
    bootstrapMessage.value = response.data.hasProtectedData
      ? `${response.data.message} Master key compatibility: ${response.data.masterKey}.`
      : response.data.message
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      bootstrapError.value =
        'The bootstrap credential is invalid, expired, or already used. Restart SignaCore to have a new one printed to standard output.'
    } else {
      bootstrapError.value = messageFrom(error, 'Database test failed.')
    }
  } finally {
    bootstrapPhase.value = 'required'
  }
}

export async function saveBootstrap() {
  bootstrapError.value = ''
  bootstrapMessage.value = ''
  bootstrapPhase.value = 'saving'
  try {
    await axios.post(createUrl, savePayload(), { headers: credentialHeaders() })
    bootstrapMessage.value = 'Bootstrap configuration saved. SignaCore is restarting to load it.'
    bootstrapForm.password = ''
    bootstrapForm.masterKey = ''
    bootstrapForm.bootstrapCredential = ''
    bootstrapPhase.value = 'restarting'
    pollForRestartedHost()
  } catch (error) {
    const status = axios.isAxiosError(error) ? error.response?.status : undefined
    bootstrapError.value = saveMessageFrom(status, error)
    bootstrapPhase.value = 'required'
  }
}

function pollForRestartedHost() {
  const started = Date.now()
  const timer = window.setInterval(async () => {
    try {
      const response = await axios.get<InstallationStatus>(statusUrl, {
        timeout: 3000,
        validateStatus: () => true,
      })
      // The bootstrap-mode host reports this phase; anything else — including the entry no longer
      // existing once the restarted host no longer maps it — means the restart completed.
      if (response.status !== 200 || response.data.phase !== 'bootstrap_configuration') {
        window.clearInterval(timer)
        window.location.assign('/setup')
        return
      }
    } catch {
      // The process is expected to disappear briefly while its supervisor restarts it.
    }

    if (Date.now() - started > 5 * 60 * 1000) {
      window.clearInterval(timer)
      bootstrapError.value =
        'The service did not restart within five minutes. Restart it manually and reopen this page.'
      bootstrapPhase.value = 'required'
    }
  }, 2000)
}
