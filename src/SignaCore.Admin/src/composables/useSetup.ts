import axios from 'axios'
import { reactive, ref } from 'vue'

/**
 * First-run setup state.
 *
 * The setup surface deliberately does not go through the admin API client: there is no session to
 * carry, and the shared ServiceMantle setup entry is the only write surface that exists while the
 * installation is pending. The fixed X-ServiceMantle-Request header is the shared entry's
 * cross-site request guard.
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
}

const statusUrl = '/management/v1/setup'
const completeUrl = '/management/v1/setup'
const unsafeRequestHeader = 'X-ServiceMantle-Request'

// Mirrors the server's IdentityConstants.MaxUsernameLength; the shared 400 carries no field-level
// reason, so the obvious mistakes are caught here with a specific message.
const maxUsernameLength = 100

const validationFailureMessage =
  '提交内容未通过校验：请检查公开地址、JWT Audience、用户名长度（1-' + maxUsernameLength + '）和密码策略'

function messageForStatus(status: number | undefined, fallback: string) {
  if (status === 400) {
    return validationFailureMessage
  }
  if (status === 401) {
    return '初始化码无效或已过期。'
  }
  if (status === 429) {
    return '尝试次数过多，请稍后再试。'
  }
  if (status === 503) {
    return '服务暂不可用，请稍后重试。'
  }
  return fallback
}

function errorMessage(error: unknown, fallback: string) {
  if (axios.isAxiosError(error)) {
    return messageForStatus(error.response?.status, error.message)
  }

  return error instanceof Error ? error.message : fallback
}

/** Returns true when the service is pending first-run setup. */
export async function probeSetupStatus(): Promise<boolean> {
  try {
    const response = await axios.get<SetupStatus>(statusUrl, { timeout: 5000 })
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

// Client-side pre-checks for the two fields whose shape is fixed, because the shared 400 answer
// carries no field-level reason. The server remains the authority.
function prevalidateForm(): string | null {
  const publicBaseUrl = setupForm.publicBaseUrl.trim()
  let parsedBaseUrl: URL | null = null
  try {
    parsedBaseUrl = new URL(publicBaseUrl)
  } catch {
    parsedBaseUrl = null
  }
  if (
    !parsedBaseUrl ||
    (parsedBaseUrl.protocol !== 'http:' && parsedBaseUrl.protocol !== 'https:') ||
    !parsedBaseUrl.hostname
  ) {
    return '公开地址必须是 http(s) 绝对地址。'
  }

  const username = setupForm.username.trim()
  if (username.length < 1 || username.length > maxUsernameLength) {
    return '用户名长度须在 1-' + maxUsernameLength + ' 个字符之间。'
  }

  return null
}

export async function submitSetup() {
  setupError.value = ''

  // The confirmation exists only for this client-side comparison; the server never sees it.
  if (setupForm.password !== setupForm.confirmPassword) {
    setupError.value = '两次输入的密码不一致。'
    return
  }

  const prevalidationFailure = prevalidateForm()
  if (prevalidationFailure) {
    setupError.value = prevalidationFailure
    return
  }

  setupPhase.value = 'saving'
  try {
    await axios.post(
      completeUrl,
      {
        code: setupForm.setupCode.trim(),
        input: {
          publicBaseUrl: setupForm.publicBaseUrl.trim(),
          allowNonHttpsIssuer: setupForm.allowNonHttpsIssuer,
          jwtAudience: setupForm.jwtAudience.trim(),
          username: setupForm.username.trim(),
          password: setupForm.password,
        },
      },
      { headers: { [unsafeRequestHeader]: '1' } },
    )

    // The plaintext password only ever existed to be hashed by the server; drop it here too.
    setupForm.password = ''
    setupForm.confirmPassword = ''
    setupForm.setupCode = ''
    setupPhase.value = 'restarting'
    pollUntilAvailable()
  } catch (error) {
    const status = axios.isAxiosError(error) ? error.response?.status : undefined
    // Another instance completed the installation first; this process is restarting into the
    // normal host just like the winner's, so it is not an error the operator must act on.
    if (status === 409) {
      setupError.value = ''
      setupForm.password = ''
      setupForm.confirmPassword = ''
      setupForm.setupCode = ''
      setupPhase.value = 'restarting'
      pollUntilAvailable()
      return
    }
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
