import axios from 'axios'
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { adminClient } from '../services/apiClient'
import { getErrorMessage, type AdminSession } from '../services/adminApi'
import { loadAllDomains, resetAllDomains } from './sessionHooks'

/* 标题来源：后端运行时按 APP_TITLE 环境变量注入 window.__APP_TITLE__（见 Host/Program.cs），
   页面内所有标题与浏览器 tab 标题同源；缺省值为服务名 */
const appTitle = window.__APP_TITLE__ || 'SignaCore'

const isAuthenticated = ref(false)
const checkingSession = ref(true)
const loggingIn = ref(false)
const session = ref<AdminSession | null>(null)

const loginForm = reactive({
  username: '',
  password: '',
  rememberMe: true,
})

function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401
}

function handleApiError(prefix: string, error: unknown) {
  if (isUnauthorized(error)) {
    resetAdminState()
    ElMessage.error('登录状态已失效，请重新登录。')
    return
  }

  ElMessage.error(`${prefix}: ${getErrorMessage(error)}`)
}

function resetAdminState() {
  isAuthenticated.value = false
  session.value = null
  resetAllDomains()
}

async function restoreSession() {
  checkingSession.value = true
  try {
    session.value = await adminClient.getCurrentSession()
    isAuthenticated.value = true
    await loadAllDomains()
  } catch (error) {
    if (!isUnauthorized(error)) {
      ElMessage.error(`会话检查失败: ${getErrorMessage(error)}`)
    }
    resetAdminState()
  } finally {
    checkingSession.value = false
  }
}

async function handleLogin() {
  if (!loginForm.username || !loginForm.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }

  loggingIn.value = true
  try {
    await adminClient.login({
      username: loginForm.username,
      password: loginForm.password,
      rememberMe: loginForm.rememberMe,
    })
    session.value = await adminClient.getCurrentSession()
    isAuthenticated.value = true
    loginForm.username = ''
    loginForm.password = ''
    ElMessage.success('登录成功')
    await loadAllDomains()
  } catch (error) {
    ElMessage.error(`登录失败: ${getErrorMessage(error)}`)
  } finally {
    loggingIn.value = false
  }
}

async function handleLogout() {
  try {
    await adminClient.logout()
    ElMessage.success('已退出登录')
  } catch {
    // ignore
  }
  resetAdminState()
}

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
export { appTitle, isAuthenticated, checkingSession, loggingIn, session, loginForm, isUnauthorized, handleApiError, resetAdminState, restoreSession, handleLogin, handleLogout }
