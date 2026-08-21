<script setup lang="ts">
import { useAdminSecurity } from "../../composables/admin/useAdminSecurity";
import { formatDate } from "../../utils/format";

const {
  auditLogs,
  auditTotal,
  auditPage,
  auditLoading,
  auditError,
  auditFilters,
  auditPages,
  loadAuditLogs,
  searchAudit,
  tokenModalOpen,
} = useAdminSecurity();
</script>

<template>
  <section class="console-view">
    <div class="console-page-heading">
      <div>
        <p class="console-eyebrow">SECURITY CENTER</p>
        <h1>审计与会话</h1>
        <p>追踪管理操作，必要时按原始 refresh token 撤销会话。</p>
      </div>
      <button class="console-button danger" @click="tokenModalOpen = true">
        撤销 refresh token
      </button>
    </div>
    <article class="console-panel list-panel">
      <div class="panel-heading">
        <div>
          <p class="console-eyebrow">AUDIT TRAIL</p>
          <h2>审计日志</h2>
        </div>
        <span class="panel-note">后端默认保留 365 天</span>
      </div>
      <div class="filter-bar">
        <div class="console-search">
          <span>⌕</span
          ><input
            v-model="auditFilters.action"
            placeholder="操作名称"
            @keyup.enter="searchAudit"
          />
        </div>
        <select
          v-model="auditFilters.targetType"
          class="console-select"
          aria-label="目标类型"
        >
          <option value="">所有目标类型</option>
          <option value="Account">账户</option>
          <option value="AppRegistration">应用</option>
          <option value="RefreshToken">Refresh token</option>
          <option value="Bootstrap">引导配置</option>
        </select>
        <div class="console-search">
          <span>#</span
          ><input
            v-model="auditFilters.targetId"
            placeholder="目标 ID"
            @keyup.enter="searchAudit"
          />
        </div>
        <button class="console-button secondary compact" @click="searchAudit">
          筛选
        </button>
      </div>
      <div v-if="auditLoading" class="console-table-state">
        <span class="console-spinner"></span>读取审计记录…
      </div>
      <div v-else-if="auditError" class="console-table-state error">
        {{ auditError }}
        <button class="text-button" @click="loadAuditLogs">重试</button>
      </div>
      <div v-else-if="!auditLogs.length" class="console-table-state">
        <span class="big-state-icon">⌁</span><b>没有审计记录</b
        ><small>调整筛选条件或等待新的管理操作。</small>
      </div>
      <div v-else class="console-table-scroll">
        <table class="console-table audit-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>操作</th>
              <th>目标</th>
              <th>执行者</th>
              <th>客户端</th>
              <th>关联 ID</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="item in auditLogs"
              :key="`${item.createdAt}-${item.correlationId}`"
            >
              <td>{{ formatDate(item.createdAt) }}</td>
              <td>
                <b>{{ item.action }}</b
                ><small class="table-secondary">{{
                  item.description || "—"
                }}</small>
              </td>
              <td>
                <span class="mono">{{ item.targetType }}</span
                ><small class="table-secondary mono">{{ item.targetId }}</small>
              </td>
              <td>{{ item.actorName || "系统" }}</td>
              <td class="mono">{{ item.clientIp || "—" }}</td>
              <td class="mono">{{ item.correlationId || "—" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="console-pager">
        <span>共 {{ auditTotal }} 条记录</span
        ><button
          :disabled="auditPage <= 1"
          @click="
            auditPage--;
            loadAuditLogs();
          "
        >
          ←</button
        ><button
          :disabled="auditPage >= auditPages"
          @click="
            auditPage++;
            loadAuditLogs();
          "
        >
          →
        </button>
      </div>
    </article>
  </section>
</template>
