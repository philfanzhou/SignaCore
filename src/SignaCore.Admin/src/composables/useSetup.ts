import axios from 'axios'
import { reactive, ref } from 'vue'

/**
 * First-run setup state.
 *
 * The setup surface deliberately does not go through the admin API client: there is no session to
 * carry, and the only two endpoints that exist while installation is pending are these.
 */

export type SetupPhase = 'checking' | 'pending' | 'saving' | 'restarting' | 'completed'

export const setupPhase = ref<SetupPhase>('checking')
export const setupError = ref('')

export const setupForm = reactive({
  publicBaseUrl: '',
  allowNonHttpsIssuer: false,
  jwtAudience: 'SignaCore.Services',
  username: '',
  password: '',
  confirmPassword: '',
  setupCode: '',
})

interface SetupStatus {
  status: 'pending' | 'completed'
  installationId: string
  restarting: boolean
  nextUrl: string
}

function errorMessage(error: unknown, fallback: string) {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { message?: string } | undefined
    if (data?.message) {
      return data.message
    }
    if (error.response?.status === 429) {
      return '尝试次数过多，请稍后再试。'
    }
    return error.message
  }

  return error instanceof Error ? error.message : fallback
}

/** Returns true when the service is pending first-run setup. */
export async function probeSetupStatus(): Promise<boolean> {
  try {
    const response = await axios.get<SetupStatus>('/api/setup/status', { timeout: 5000 })
    return response.data.status === 'pending'
  } catch {
    // A service that cannot answer the status probe is either mid-restart or not a setup-mode host.
    // Either way the console should fall back to its normal login flow.
    return false
  }
}

export function prefillPublicBaseUrl() {
  if (!setupForm.publicBaseUrl) {
    setupForm.publicBaseUrl = window.location.origin
  }
}

export async function submitSetup() {
  setupError.value = ''

  if (setupForm.password !== setupForm.confirmPassword) {
    setupError.value = '两次输入的密码不一致。'
    return
  }

  setupPhase.value = 'saving'
  try {
    await axios.post('/api/setup/complete', {
      publicBaseUrl: setupForm.publicBaseUrl.trim(),
      allowNonHttpsIssuer: setupForm.allowNonHttpsIssuer,
      jwtAudience: setupForm.jwtAudience.trim(),
      username: setupForm.username.trim(),
      password: setupForm.password,
      confirmPassword: setupForm.confirmPassword,
      setupCode: setupForm.setupCode.trim(),
    })

    // The plaintext password only ever existed to be hashed by the server; drop it here too.
    setupForm.password = ''
    setupForm.confirmPassword = ''
    setupForm.setupCode = ''
    setupPhase.value = 'restarting'
    pollUntilAvailable()
  } catch (error) {
    setupError.value = errorMessage(error, '初始化失败，请重试。')
    setupPhase.value = 'pending'
  }
}

/**
 * The host stops itself after the response completes so a supervisor can restart it into the normal
 * host. Poll readiness rather than guessing how long that takes.
 */
function pollUntilAvailable() {
  const started = Date.now()
  const timer = window.setInterval(async () => {
    try {
      const response = await axios.get('/health/ready', {
        timeout: 3000,
        validateStatus: () => true,
      })
      if (response.status === 200) {
        window.clearInterval(timer)
        setupPhase.value = 'completed'
        window.location.assign('/admin')
        return
      }
    } catch {
      // The process is down between stop and restart; keep waiting.
    }

    if (Date.now() - started > 5 * 60 * 1000) {
      window.clearInterval(timer)
      setupError.value =
        '服务在 5 分钟内未恢复。如果 SignaCore 不是由 Docker、systemd 或 Kubernetes 托管，请手动重新启动它。'
    }
  }, 2000)
}
