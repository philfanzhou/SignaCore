<script setup lang="ts">
import { nextTick, onMounted, ref, watch } from 'vue'
import { appTitle, isAuthenticated, session } from '../composables/useSession'
import { useViewNav } from '../composables/useViewNav'
import { I } from '../utils/icons'
import { getInitials } from '../utils/format'

const { activeTab, sidebarOpen, navItems, navigateTo } = useViewNav()

const navIndicatorStyle = ref<{ transform: string; opacity: number }>({ transform: 'translateY(0)', opacity: 0 })
const navRef = ref<HTMLElement | null>(null)

function updateNavIndicator() {
  const nav = navRef.value
  if (!nav) {
    navIndicatorStyle.value = { transform: 'translateY(0)', opacity: 0 }
    return
  }
  const active = nav.querySelector('.nav-item.active') as HTMLElement | null
  if (!active) {
    navIndicatorStyle.value = { transform: 'translateY(0)', opacity: 0 }
    return
  }
  navIndicatorStyle.value = {
    transform: `translateY(${active.offsetTop}px)`,
    opacity: 1,
  }
}

watch(activeTab, () => {
  nextTick(() => updateNavIndicator())
})

/* 登录/会话恢复后侧边栏才渲染，此时初始化 nav 指示器位置 */
watch(isAuthenticated, (authed) => {
  if (authed) nextTick(() => updateNavIndicator())
})

onMounted(() => {
  nextTick(() => updateNavIndicator())
})
</script>

<template>
  <aside class="sidebar" :class="{ open: sidebarOpen }">
    <div class="brand">
      <div class="brand-mark">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.idCard"></svg>
      </div>
      <div class="brand-text">{{ appTitle }}<span>管理控制台</span></div>
    </div>
    <nav class="nav" ref="navRef">
      <div class="nav-indicator" :style="navIndicatorStyle"></div>
      <div class="nav-label">SignaCore</div>
      <button
        v-for="item in navItems"
        :key="item.key"
        class="nav-item"
        :class="{ active: activeTab === item.key }"
        @click="navigateTo(item.key)"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I[item.icon]"></svg>
        <span>{{ item.label }}</span>
      </button>
    </nav>
    <div class="sidebar-foot">
      <div class="admin-chip">
        <div class="avatar">{{ getInitials(session?.username || 'A') }}</div>
        <div>
          <div class="name">{{ session?.username || '管理员' }}</div>
          <div class="role">引导超级管理员</div>
        </div>
      </div>
    </div>
  </aside>

  <div class="overlay sidebar-overlay" :class="{ open: sidebarOpen }" @click="sidebarOpen = false"></div>
</template>
