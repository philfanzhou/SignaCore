<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import AuthView from './components/AuthView.vue'
import AppSidebar from './components/AppSidebar.vue'
import AppTopbar from './components/AppTopbar.vue'
import StatBar from './components/StatBar.vue'
import UsersTab from './components/UsersTab.vue'
import AppsTab from './components/AppsTab.vue'
import CallbacksTab from './components/CallbacksTab.vue'
import TokensTab from './components/TokensTab.vue'
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

const { activeTab, viewLeaving } = useViewNav()
const { startClock, stopClock } = useClock()

onMounted(() => {
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
  <AuthView v-if="checkingSession || !isAuthenticated" />

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
      </main>
    </div>
  </div>

  <UserDrawer />
  <AppDrawer />
  <CreateUserModal />
  <CreatePhoneUserModal />
  <CreateAppModal />
  <SecretModal />
  <EditRemarkModal />
  <DeleteAppModal />
</template>
