import axios from 'axios'
import { reactive, ref } from 'vue'

export type BootstrapPhase = 'checking' | 'required' | 'testing' | 'saving' | 'restarting'

export interface BootstrapProvider {
  provider: string
  serverVersions: string[]
  defaultPort: number | null
  singleInstanceOnly: boolean
}

interface BootstrapStatus {
  status: 'required' | 'configured' | 'restarting'
  filePath: string
  supportedProviders: BootstrapProvider[]
}

interface BootstrapInspection {
  target: string
  endpoint: string
  canConnect: boolean
  hasProtectedData: boolean
  masterKey: string
  message: string
}

export const bootstrapPhase = ref<BootstrapPhase>('checking')
export const bootstrapError = ref('')
export const bootstrapMessage = ref('')
export const bootstrapFilePath = ref('')
export const bootstrapProviders = ref<BootstrapProvider[]>([])
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
  bootstrapCode: '',
})

function messageFrom(error: unknown, fallback: string) {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { message?: string; detail?: string } | undefined
    return data?.message || data?.detail || error.message
  }
  return error instanceof Error ? error.message : fallback
}

export async function probeBootstrapStatus(): Promise<boolean> {
  try {
    const response = await axios.get<BootstrapStatus>('/api/bootstrap/status', { timeout: 5000 })
    bootstrapFilePath.value = response.data.filePath || ''
    bootstrapProviders.value = response.data.supportedProviders || []
    bootstrapPhase.value = response.data.status === 'restarting' ? 'restarting' : 'required'
    const current = bootstrapProviders.value.find(item => item.provider === bootstrapForm.provider)
    if (current) applyProviderDefaults(current)
    return response.data.status !== 'configured'
  } catch {
    return false
  }
}

export function applyProviderDefaults(provider: BootstrapProvider) {
  bootstrapForm.provider = provider.provider
  bootstrapForm.serverVersion = provider.serverVersions[0] || ''
  bootstrapForm.port = provider.defaultPort
}

function databasePayload() {
  if (bootstrapAdvanced.value) {
    return {
      provider: bootstrapForm.provider,
      serverVersion: bootstrapForm.serverVersion || null,
      connectionString: bootstrapForm.connectionString.trim(),
    }
  }

  return {
    provider: bootstrapForm.provider,
    serverVersion: bootstrapForm.serverVersion || null,
    host: bootstrapForm.host.trim(),
    port: bootstrapForm.port,
    database: bootstrapForm.database.trim(),
    username: bootstrapForm.username.trim(),
    password: bootstrapForm.password,
    filePath: bootstrapForm.filePath.trim(),
  }
}

function requestPayload() {
  return {
    database: databasePayload(),
    installMode: bootstrapForm.installMode,
    masterKey: bootstrapForm.installMode === 'existing' ? bootstrapForm.masterKey : null,
    bootstrapCode: bootstrapForm.bootstrapCode.trim(),
  }
}

export async function testBootstrap() {
  bootstrapError.value = ''
  bootstrapMessage.value = ''
  bootstrapPhase.value = 'testing'
  try {
    const response = await axios.post<BootstrapInspection>('/api/bootstrap/test', requestPayload())
    bootstrapMessage.value = response.data.hasProtectedData
      ? `${response.data.message} Master key compatibility: ${response.data.masterKey}.`
      : response.data.message
  } catch (error) {
    bootstrapError.value = messageFrom(error, 'Database test failed.')
  } finally {
    bootstrapPhase.value = 'required'
  }
}

export async function saveBootstrap() {
  bootstrapError.value = ''
  bootstrapMessage.value = ''
  bootstrapPhase.value = 'saving'
  try {
    const response = await axios.post<{ message: string }>('/api/bootstrap/save', requestPayload())
    bootstrapMessage.value = response.data.message
    bootstrapForm.password = ''
    bootstrapForm.masterKey = ''
    bootstrapForm.bootstrapCode = ''
    bootstrapPhase.value = 'restarting'
    pollForConfiguredHost()
  } catch (error) {
    bootstrapError.value = messageFrom(error, 'Bootstrap configuration could not be saved.')
    bootstrapPhase.value = 'required'
  }
}

function pollForConfiguredHost() {
  const started = Date.now()
  const timer = window.setInterval(async () => {
    try {
      const response = await axios.get<BootstrapStatus>('/api/bootstrap/status', { timeout: 3000 })
      if (response.data.status === 'configured') {
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
