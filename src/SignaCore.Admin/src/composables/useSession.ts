import axios from 'axios'
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { adminClient } from '../services/apiClient'
import { getErrorMessage, type AdminSession } from '../services/adminApi'
import {
  clearCredential, currentCredential, currentGeneration, isCurrentGeneration,
  onCredentialExpired, publishCredential, SupersededSessionError,
} from '../services/managementBearer'
import { loadAllDomains, resetAllDomains } from './sessionHooks'

/* 标题来源：后端运行时按 APP_TITLE 环境变量注入 window.__APP_TITLE__（见 Host/Program.cs），
   页面内所有标题与浏览器 tab 标题同源；缺省值为服务名 */
const appTitle = window.__APP_TITLE__ || 'SignaCore'

const isAuthenticated = ref(false)
const checkingSession = ref(true)
const loggingIn = ref(false)
const session = ref<AdminSession | null>(null)
let expiryTimer: ReturnType<typeof setTimeout> | undefined

const loginForm = reactive({
  username: '',
  password: '',
})

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401
}

function handleApiError(prefix: string, error: unknown) {
  if (error instanceof SupersededSessionError) return
  if (isUnauthorized(error)) {
    resetAdminState()
    ElMessage.error('Your management session has expired. Sign in again.')
    return
  }

  if (axios.isAxiosError(error) && error.response?.status === 503) {
    ElMessage.error('The management service is temporarily unavailable. Try again.')
    return
  }

  ElMessage.error(`${prefix}: ${getErrorMessage(error)}`)
}

function resetAdminState() {
  if (expiryTimer !== undefined) clearTimeout(expiryTimer)
  expiryTimer = undefined
  clearCredential()
  isAuthenticated.value = false
  session.value = null
  resetAllDomains()
}

function restoreSession() {
  // A page load never restores a bearer from browser persistence or from a cookie.
  resetAdminState()
  checkingSession.value = false
}

function scheduleExpiry(generation: number, expiresAtMs: number) {
  if (expiryTimer !== undefined) clearTimeout(expiryTimer)
  expiryTimer = setTimeout(() => {
    if (!isCurrentGeneration(generation)) return
    resetAdminState()
    ElMessage.error('Your 15-minute management session has expired. Sign in again.')
  }, Math.max(0, expiresAtMs - Date.now()))
}

/** 共享登录入口的固定拒绝文案：401 不区分密码错误与无管理权限，避免泄露账号状态。 */
function loginErrorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status
    if (status === 401) {
      return 'The credentials are invalid or this account has no management access.'
    }
    if (status === 429 || status === 503) {
      return 'Sign-in is temporarily unavailable. Try again later.'
    }
  }
  return 'Sign-in could not be completed. Try again.'
}

async function handleLogin() {
  if (!loginForm.username || !loginForm.password) {
    ElMessage.warning('Enter a username and password.')
    return
  }
  if (loggingIn.value) return

  loggingIn.value = true
  const attemptGeneration = currentGeneration()
  const payload = { username: loginForm.username, password: loginForm.password }
  loginForm.password = ''
  let issuedGeneration: number | undefined
  try {
    const response = await adminClient.login(payload)
    if (!isCurrentGeneration(attemptGeneration)) return
    const issued = publishCredential(response)
    issuedGeneration = issued.generation
    scheduleExpiry(issued.generation, issued.expiresAtMs)
    const current = await adminClient.getCurrentSession()
    if (!isCurrentGeneration(issued.generation)) return
    if (!current.isAuthenticated) throw new Error('The management session could not be verified.')
    session.value = current
    isAuthenticated.value = true
    loginForm.username = ''
    await loadAllDomains()
    if (isCurrentGeneration(issued.generation)) ElMessage.success('Signed in.')
  } catch (error) {
    if (error instanceof SupersededSessionError) return
    if (issuedGeneration !== undefined && isCurrentGeneration(issuedGeneration)) resetAdminState()
    if (issuedGeneration === undefined && !isCurrentGeneration(attemptGeneration)) return
    ElMessage.error(`Sign-in failed: ${loginErrorMessage(error)}`)
  } finally {
    loginForm.password = ''
    loggingIn.value = false
  }
}

async function handleLogout() {
  const credential = currentCredential()
  resetAdminState()
  const clearedGeneration = currentGeneration()
  if (!credential) {
    ElMessage.warning('Local sign-out completed. Server revocation was not confirmed; the credential expires within 15 minutes.')
    return
  }
  try {
    await adminClient.logout(credential.token)
    if (isCurrentGeneration(clearedGeneration)) ElMessage.success('Signed out and server session revoked.')
  } catch {
    if (isCurrentGeneration(clearedGeneration)) {
      ElMessage.warning('Local sign-out completed. Server revocation was not confirmed; the credential expires at its original expiry time.')
    }
  }
}

onCredentialExpired(() => {
  resetAdminState()
  ElMessage.error('Your 15-minute management session has expired. Sign in again.')
})

export function useSession() {
  return {
    appTitle,
    isAuthenticated,
    checkingSession,
    loggingIn,
    session,
    loginForm,
    isUnauthorized,
    handleApiError,
    resetAdminState,
    restoreSession,
    handleLogin,
    handleLogout,
  }
}

/* 模块级导出，供域 composable 直接引用（单向依赖：域 → session） */
export { appTitle, isAuthenticated, checkingSession, loggingIn, session, loginForm, isUnauthorized, handleApiError, resetAdminState, restoreSession, handleLogin, handleLogout, loginErrorMessage }
