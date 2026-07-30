import { computed, watch } from 'vue'
import { useUsers } from './useUsers'
import { useApps } from './useApps'

const {
  userDrawerVisible,
  showCreateUserDialog,
  showCreatePhoneUserDialog,
  editRemarkOpen,
  closeUserDrawer,
} = useUsers()

const {
  appDrawerVisible,
  showCreateAppDialog,
  showSecretDialog,
  secretSavedConfirmed,
  deleteAppOpen,
  closeAppDrawer,
} = useApps()

/* 浮层打开期间锁定 body 滚动（样稿行为） */
const anyFloatingOpen = computed(() =>
  userDrawerVisible.value || appDrawerVisible.value ||
  showCreateUserDialog.value || showCreatePhoneUserDialog.value || showCreateAppDialog.value ||
  showSecretDialog.value || editRemarkOpen.value || deleteAppOpen.value
)

/* Esc 关闭浮层（样稿行为）：modal 优先于 drawer；ElMessageBox 打开时不拦截 */
function handleEscapeKey(e: KeyboardEvent) {
  if (e.key !== 'Escape') return
  if (document.querySelector('.el-message-box__wrapper')) return
  if (showCreateUserDialog.value) { showCreateUserDialog.value = false; return }
  if (showCreatePhoneUserDialog.value) { showCreatePhoneUserDialog.value = false; return }
  if (showCreateAppDialog.value) { showCreateAppDialog.value = false; return }
  if (showSecretDialog.value) { showSecretDialog.value = false; secretSavedConfirmed.value = false; return }
  if (editRemarkOpen.value) { editRemarkOpen.value = false; return }
  if (deleteAppOpen.value) { deleteAppOpen.value = false; return }
  if (userDrawerVisible.value) { closeUserDrawer(); return }
  if (appDrawerVisible.value) { closeAppDrawer() }
}

let initialized = false

export function setupOverlay() {
  if (initialized) return
  initialized = true
  watch(anyFloatingOpen, (open) => {
    document.body.style.overflow = open ? 'hidden' : ''
  })
  window.addEventListener('keydown', handleEscapeKey)
}

export function teardownOverlay() {
  window.removeEventListener('keydown', handleEscapeKey)
  document.body.style.overflow = ''
}

export function useOverlay() {
  return {
    anyFloatingOpen,
    handleEscapeKey,
    setupOverlay,
    teardownOverlay,
  }
}
