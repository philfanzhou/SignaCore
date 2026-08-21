<script setup lang="ts">
import { onMounted, ref } from 'vue'
import AuthView from './components/AuthView.vue'
import BootstrapView from './components/BootstrapView.vue'
import SetupView from './components/SetupView.vue'
import AdminConsole from './components/AdminConsole.vue'
import { isAuthenticated, checkingSession, restoreSession } from './composables/useSession'
import { probeSetupStatus, setupPhase } from './composables/useSetup'
import { bootstrapPhase, probeBootstrapStatus } from './composables/useBootstrap'

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
})
</script>

<template>
  <!-- 安装状态探测期间不渲染任何界面，避免登录页与初始化页闪烁 -->
  <div v-if="bootstrapping" class="auth-page"></div>

  <BootstrapView v-else-if="needsBootstrap" />

  <SetupView v-else-if="needsSetup" />

  <AuthView v-else-if="checkingSession || !isAuthenticated" />

  <!-- 已登录主界面：全新信息架构与交互，真实数据仍由管理 API 驱动。 -->
  <AdminConsole v-else-if="isAuthenticated" />
</template>
