<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import AuthView from './components/AuthView.vue'
import BootstrapView from './components/BootstrapView.vue'
import SetupView from './components/SetupView.vue'
import AppSidebar from './components/AppSidebar.vue'
import AppTopbar from './components/AppTopbar.vue'
import StatBar from './components/StatBar.vue'
import UsersTab from './components/UsersTab.vue'
import AppsTab from './components/AppsTab.vue'
import CallbacksTab from './components/CallbacksTab.vue'
import TokensTab from './components/TokensTab.vue'
import SettingsTab from './components/SettingsTab.vue'
import UserDrawer from './components/UserDrawer.vue'
import AppDrawer from './components/AppDrawer.vue'
import CreateUserModal from './components/modals/CreateUserModal.vue'
import CreatePhoneUserModal from './components/modals/CreatePhoneUserModal.vue'
import CreateAppModal from './components/modals/CreateAppModal.vue'
import SecretModal from './components/modals/SecretModal.vue'
import EditRemarkModal from './components/modals/EditRemarkModal.vue'
import DeleteAppModal from './components/modals/DeleteAppModal.vue'
import { isAuthenticated, checkingSession, restoreSession } from './composables/useSession'
import { useViewNav } from './composables/useViewNav'
import { useClock } from './composables/useClock'
import { setupOverlay, teardownOverlay } from './composables/useOverlay'
import { disposeUsers } from './composables/useUsers'
import { disposeApps } from './composables/useApps'
import { probeSetupStatus, setupPhase } from './composables/useSetup'
import { bootstrapPhase, probeBootstrapStatus } from './composables/useBootstrap'

const { activeTab, viewLeaving } = useViewNav()
const { startClock, stopClock } = useClock()

/* 首次配置与正常控制台是同一个 SPA 构建。服务端在 Pending 期间会把浏览器导航重定向到 /setup，
   但直接访问 / 也要能正确落到初始化页，所以这里始终先探一次安装状态。 */
const bootstrapping = ref(true)
const needsBootstrap = ref(false)
const needsSetup = ref(false)

onMounted(async () => {
  needsBootstrap.value = await probeBootstrapStatus()
  if (needsBootstrap.value) {
    bootstrapPhase.value = 'required'
    bootstrapping.value = false
    return
  }

  needsSetup.value = await probeSetupStatus()
  bootstrapping.value = false

  if (needsSetup.value) {
    setupPhase.value = 'pending'
    return
  }

  restoreSession()
  startClock()
  setupOverlay()
})

onUnmounted(() => {
  stopClock()
  disposeUsers()
  disposeApps()
  teardownOverlay()
})
</script>

<template>
  <!-- 安装状态探测期间不渲染任何界面，避免登录页与初始化页闪烁 -->
  <div v-if="bootstrapping" class="auth-page"></div>

  <BootstrapView v-else-if="needsBootstrap" />

  <SetupView v-else-if="needsSetup" />

  <AuthView v-else-if="checkingSession || !isAuthenticated" />

  <!-- 已登录主界面 -->
  <div v-else class="app-shell">
    <AppSidebar />

    <div class="main">
      <AppTopbar />

      <main class="view-wrap" :class="{ leaving: viewLeaving }">
        <StatBar />
        <UsersTab v-if="activeTab === 'users'" />
        <AppsTab v-if="activeTab === 'apps'" />
        <CallbacksTab v-if="activeTab === 'callbacks'" />
        <TokensTab v-if="activeTab === 'tokens'" />
        <SettingsTab v-if="activeTab === 'settings'" />
      </main>
    </div>
  </div>

  <!-- 初始化阶段没有会话，也没有可操作的数据域，抽屉与弹窗一并不挂载 -->
  <template v-if="!bootstrapping && !needsSetup">
    <UserDrawer />
    <AppDrawer />
    <CreateUserModal />
    <CreatePhoneUserModal />
    <CreateAppModal />
    <SecretModal />
    <EditRemarkModal />
    <DeleteAppModal />
  </template>
</template>
