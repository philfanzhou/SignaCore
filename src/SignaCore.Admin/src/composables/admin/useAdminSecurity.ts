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
    });
    auditLogs.value = result.items;
    auditTotal.value = result.total;
  } catch (error) {
    auditError.value = getErrorMessage(error);
    handleApiError("加载审计日志失败", error);
  } finally {
    auditLoading.value = false;
  }
}

function searchAudit() {
  auditPage.value = 1;
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
    revokeToken,
    closeTokenModal,
  };
}
