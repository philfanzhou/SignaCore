<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { useUsers } from '../composables/useUsers'
import { useApps } from '../composables/useApps'
import { I } from '../utils/icons'

const { users, userTotal } = useUsers()
const { apps, activeAppsCount, disabledAppsCount } = useApps()

/* 数字滚动入场 */
function runCounters(root: HTMLElement | null) {
  if (!root) return
  root.querySelectorAll<HTMLElement>('[data-count]').forEach(elm => {
    const target = parseFloat(elm.dataset.count || '0')
    const dur = 900
    const t0 = performance.now()
    const suffix = elm.dataset.suffix || ''
    const tick = (t: number) => {
      const p = Math.min((t - t0) / dur, 1)
      const e = 1 - Math.pow(1 - p, 3)
      elm.textContent = Math.round(target * e).toLocaleString('en-US') + suffix
      if (p < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  })
}

const statGridRef = ref<HTMLElement | null>(null)
watch([userTotal, apps, activeAppsCount, disabledAppsCount], () => {
  nextTick(() => runCounters(statGridRef.value))
})
</script>

<template>
  <!-- 统计栏 -->
  <div class="stat-grid" ref="statGridRef">
    <div class="card hoverable stat-card">
      <div class="stat-label">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.users"></svg>
        用户总数
      </div>
      <div class="stat-num" :data-count="userTotal">0</div>
      <div class="stat-foot">
        <span>当前页 {{ users.length }} 条</span>
      </div>
    </div>
    <div class="card hoverable stat-card">
      <div class="stat-label">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
        OAuth 应用
      </div>
      <div class="stat-num" :data-count="apps.length">0</div>
      <div class="stat-foot">{{ activeAppsCount }} 个已启用 · {{ disabledAppsCount }} 个停用</div>
    </div>
    <div class="card hoverable stat-card">
      <div class="stat-label">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.zap"></svg>
        已启用应用
      </div>
      <div class="stat-num" :data-count="activeAppsCount">0</div>
      <div class="stat-foot">调用方在线接入</div>
    </div>
    <div class="card hoverable stat-card">
      <div class="stat-label">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.warnTri"></svg>
        已停用应用
      </div>
      <div class="stat-num" :data-count="disabledAppsCount">0</div>
      <div class="stat-foot">需关注 · 检查是否下线</div>
    </div>
  </div>
</template>
