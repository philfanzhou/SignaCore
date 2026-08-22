<script setup lang="ts">
import { computed } from "vue";
import { useAdminApps } from "../../composables/admin/useAdminApps";
import { useAdminSecurity } from "../../composables/admin/useAdminSecurity";
import {
  useAdminSettings,
  type SettingsSectionKey,
} from "../../composables/admin/useAdminSettings";
import { useAdminUsers } from "../../composables/admin/useAdminUsers";
import { formatDate } from "../../utils/format";

type ViewKey =
  | "overview"
  | "identity"
  | "resources"
  | "security"
  | SettingsSectionKey;
const props = defineProps<{ navigate: (view: ViewKey) => void }>();
const { userTotal, users } = useAdminUsers();
const { apps } = useAdminApps();
const { auditLogs } = useAdminSecurity();
const { configurationVersion, runningConfigurationVersion, restartPending } =
  useAdminSettings();
const activeUsers = computed(
  () => users.value.filter((user) => user.isActive).length,
);
const activeApps = computed(
  () => apps.value.filter((app) => app.isActive).length,
);
const disabledApps = computed(
  () => apps.value.filter((app) => !app.isActive).length,
);
</script>

<template>
  <section class="console-view">
    <div class="console-page-heading">
      <div>
        <h1>概览</h1>
        <p>查看用户、应用和配置状态。</p>
      </div>
    </div>
    <div class="console-metric-grid">
      <article class="console-metric">
        <span class="metric-label">账户目录</span
        ><strong>{{ userTotal }}</strong
        ><span class="metric-foot success"
          >{{ activeUsers }} 个当前页已启用</span
        >
      </article>
      <article class="console-metric">
        <span class="metric-label">接入应用</span
        ><strong>{{ apps.length }}</strong
        ><span class="metric-foot" :class="activeApps ? 'success' : 'muted'"
          >{{ activeApps }} 个对外可用</span
        >
      </article>
      <article class="console-metric">
        <span class="metric-label">待处理信号</span
        ><strong>{{ (restartPending ? 1 : 0) + disabledApps }}</strong
        ><span
          class="metric-foot"
          :class="restartPending ? 'warning' : 'muted'"
          >{{ restartPending ? "配置等待重启" : "暂无配置重启" }}</span
        >
      </article>
      <article class="console-metric dark">
        <span class="metric-label">运行配置版本</span
        ><strong>v{{ configurationVersion }}</strong
        ><span class="metric-foot"
          >运行中 v{{ runningConfigurationVersion }}</span
        >
      </article>
    </div>
    <div class="console-two-column">
      <article class="console-panel attention-panel">
        <div class="panel-heading">
          <div>
            <h2>需要关注</h2>
          </div>
          <span class="console-count">{{
            (restartPending ? 1 : 0) + disabledApps
          }}</span>
        </div>
        <div v-if="restartPending" class="console-attention-item warning">
          <span>!</span>
          <div>
            <b>运行配置等待重启</b>
            <p>
              新的配置版本已经写入，但当前进程仍运行在 v{{
                runningConfigurationVersion
              }}。
            </p>
          </div>
          <button @click="props.navigate('settings-identity')">查看</button>
        </div>
        <div v-if="disabledApps" class="console-attention-item">
          <span>○</span>
          <div>
            <b>{{ disabledApps }} 个应用已停用</b>
            <p>确认是否仍保留对应的回调和准入配置。</p>
          </div>
          <button @click="props.navigate('resources')">查看</button>
        </div>
        <div
          v-if="!restartPending && !disabledApps"
          class="console-empty-inline"
        >
          <span>✓</span>目前没有待处理信号
        </div>
      </article>
      <article class="console-panel">
        <div class="panel-heading">
          <div>
            <h2>最近审计</h2>
          </div>
          <button class="text-button" @click="props.navigate('security')">
            全部记录 →
          </button>
        </div>
        <div v-if="auditLogs.length" class="activity-list">
          <div
            v-for="item in auditLogs.slice(0, 5)"
            :key="`${item.createdAt}-${item.action}`"
            class="activity-row"
          >
            <span class="activity-dot"></span>
            <div>
              <b>{{ item.description || item.action }}</b>
              <p>
                {{ item.actorName || "系统" }} ·
                {{ formatDate(item.createdAt) }}
              </p>
            </div>
          </div>
        </div>
        <div v-else class="console-empty-inline">
          打开安全中心加载最近审计记录
        </div>
      </article>
    </div>
  </section>
</template>
