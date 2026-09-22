import { reactive, ref, computed } from "vue";
import { adminClient } from "../../services/apiClient";
import {
  getErrorMessage,
  type AdminAuditLogItem,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { notify } from "./useAdminFeedback";

const auditLogs = ref<AdminAuditLogItem[]>([]);
const auditTotal = ref(0);
const auditPage = ref(1);
const auditPageSize = 15;
const auditLoading = ref(false);
const auditError = ref("");
const auditFilters = reactive({ action: "", targetType: "", targetId: "" });
const tokenModalOpen = ref(false);
const tokenValue = ref("");
const tokenBusy = ref(false);
const auditPages = computed(() =>
  Math.max(1, Math.ceil(auditTotal.value / auditPageSize)),
);
// keyset 分页：cursors[i] 是请求第 i+2 页时要带的 continuationCursor（第 1 页不带游标）。
// 筛选条件变化时整栈作废，从第 1 页重新开始。
const auditCursors = ref<string[]>([]);

async function loadAuditLogs() {
  auditLoading.value = true;
  auditError.value = "";
  try {
    const result = await adminClient.getAuditLogs({
      action: auditFilters.action.trim() || undefined,
      targetType: auditFilters.targetType || undefined,
      targetId: auditFilters.targetId.trim() || undefined,
      page: auditPage.value,
      pageSize: auditPageSize,
      cursor:
        auditPage.value > 1 ? auditCursors.value[auditPage.value - 1] : undefined,
    });
    auditLogs.value = result.items;
    auditTotal.value = result.totalCount;
    if (result.continuationCursor) {
      auditCursors.value[auditPage.value] = result.continuationCursor;
    }
  } catch (error) {
    auditError.value = getErrorMessage(error);
    handleApiError("加载审计日志失败", error);
  } finally {
    auditLoading.value = false;
  }
}

function searchAudit() {
  auditPage.value = 1;
  auditCursors.value = [];
  void loadAuditLogs();
}

function auditPrevPage() {
  if (auditPage.value <= 1) return;
  auditPage.value--;
  void loadAuditLogs();
}

function auditNextPage() {
  const cursor = auditCursors.value[auditPage.value];
  if (!cursor) return;
  auditPage.value++;
  void loadAuditLogs();
}

async function revokeToken() {
  if (!tokenValue.value.trim()) return notify("请输入完整 refresh token");
  tokenBusy.value = true;
  try {
    await adminClient.revokeRefreshToken(tokenValue.value.trim());
    tokenValue.value = "";
    tokenModalOpen.value = false;
    notify("refresh token 已撤销");
    void loadAuditLogs();
  } catch (error) {
    handleApiError("撤销 refresh token 失败", error);
  } finally {
    tokenBusy.value = false;
  }
}

function closeTokenModal() {
  tokenModalOpen.value = false;
  tokenValue.value = "";
}

export function useAdminSecurity() {
  return {
    auditLogs,
    auditTotal,
    auditPage,
    auditLoading,
    auditError,
    auditFilters,
    auditPages,
    tokenModalOpen,
    tokenValue,
    tokenBusy,
    loadAuditLogs,
    searchAudit,
    auditPrevPage,
    auditNextPage,
    revokeToken,
    closeTokenModal,
  };
}
