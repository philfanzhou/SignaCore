import { computed, ref } from 'vue'
import { registerSessionHooks } from './sessionHooks'

const activeTab = ref('users')
const sidebarOpen = ref(false)
const viewLeaving = ref(false)

/* nav 配置 - 与样稿的 4 个 Tab 对应（系统切换器、概览、审计 不实现，见 spec） */
const navItems = [
  { key: 'users',    label: '用户管理', icon: 'users' },
  { key: 'apps',     label: '应用注册', icon: 'app' },
  { key: 'callbacks',label: '回调管理', icon: 'shield' },
  { key: 'tokens',   label: '令牌管理', icon: 'key' },
] as const

const currentNavLabel = computed(() => navItems.find((n) => n.key === activeTab.value)?.label ?? '')

function navigateTo(tab: string) {
  if (activeTab.value === tab) return
  viewLeaving.value = true
  setTimeout(() => {
    activeTab.value = tab
    viewLeaving.value = false
    sidebarOpen.value = false
  }, 150)
}

registerSessionHooks({
  reset: () => {
    activeTab.value = 'users'
    sidebarOpen.value = false
  },
})

export function useViewNav() {
  return {
    activeTab,
    sidebarOpen,
    viewLeaving,
    navItems,
    currentNavLabel,
    navigateTo,
  }
}
