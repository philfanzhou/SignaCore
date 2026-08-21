<script setup lang="ts">
import { computed } from "vue";
import { useAdminApps } from "../../composables/admin/useAdminApps";
import { useAdminSecurity } from "../../composables/admin/useAdminSecurity";
import { useAdminSettings } from "../../composables/admin/useAdminSettings";
import { useAdminUsers } from "../../composables/admin/useAdminUsers";
import { formatDate } from "../../utils/format";

type ViewKey =
  | "overview"
  | "identity"
  | "resources"
  | "security"
  | "settings"
  | "boundary";
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
        <p class="console-eyebrow">
          CONTROL PLANE / {{ new Date().getFullYear() }}
        </p>
        <h1>运行总览</h1>
        <p>把身份、接入资源和变更风险放在同一张工作台上。</p>
      </div>
      <button
        class="console-button secondary"
        @click="props.navigate('boundary')"
      >
        查看能力边界 <span>→</span>
      </button>
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
            <p class="console-eyebrow">ATTENTION QUEUE</p>
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
          <button @click="props.navigate('settings')">查看</button>
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
            <p class="console-eyebrow">RECENT ACTIVITY</p>
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
    <article class="console-panel state-panel">
      <div class="panel-heading">
        <div>
          <p class="console-eyebrow">STATE LANGUAGE</p>
          <h2>状态语言</h2>
        </div>
        <span class="panel-note">统一反馈，避免误判</span>
      </div>
      <div class="state-grid">
        <div>
          <span class="status-pill green"><i></i>已启用</span
          ><small>可继续操作</small>
        </div>
        <div>
          <span class="status-pill amber"><i></i>等待重启</span
          ><small>变更已保存</small>
        </div>
        <div>
          <span class="status-pill gray"><i></i>未配置</span
          ><small>需要补齐</small>
        </div>
        <div>
          <span class="status-pill red"><i></i>错误</span
          ><small>可重试或联系维护者</small>
        </div>
      </div>
    </article>
  </section>
</template>
