import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { adminClient } from '../services/apiClient'
import { handleApiError } from './useSession'
import { registerSessionHooks } from './sessionHooks'

const revokingToken = ref(false)

const tokenForm = reactive({
  refreshToken: '',
})

async function handleRevokeToken() {
  if (!tokenForm.refreshToken) {
    ElMessage.warning('请输入要吊销的刷新令牌')
    return
  }

  revokingToken.value = true
  try {
    await adminClient.revokeRefreshToken(tokenForm.refreshToken)
    ElMessage.success('令牌吊销成功')
    tokenForm.refreshToken = ''
  } catch (error) {
    handleApiError('吊销令牌失败', error)
  } finally {
    revokingToken.value = false
  }
}

registerSessionHooks({
  reset: () => {
    tokenForm.refreshToken = ''
  },
})

export function useTokens() {
  return {
    revokingToken,
    tokenForm,
    handleRevokeToken,
  }
}
