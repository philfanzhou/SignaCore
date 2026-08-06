<script setup lang="ts">
import { handleLogout } from '../composables/useSession'
import { useViewNav } from '../composables/useViewNav'
import { useClock } from '../composables/useClock'
import { refreshAll } from '../composables/sessionHooks'
import { I } from '../utils/icons'

const { sidebarOpen, currentNavLabel } = useViewNav()
const { clockText } = useClock()
</script>

<template>
  <header class="topbar">
    <button class="hamburger icon-btn" @click="sidebarOpen = !sidebarOpen">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" v-html="I.menu"></svg>
    </button>
    <div class="crumb">
      <span>身份中心</span>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.chev"></svg>
      <b>{{ currentNavLabel }}</b>
    </div>
    <div class="top-right">
      <button class="icon-btn" title="刷新数据" @click="refreshAll">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.refresh"></svg>
      </button>
      <span class="env-tag">内网环境</span>
      <span class="clock">{{ clockText }}</span>
      <button class="logout-btn" title="退出登录" @click="handleLogout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.logout"></svg>
      </button>
    </div>
  </header>
</template>
