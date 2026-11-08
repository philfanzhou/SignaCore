import type { Ref } from "vue";
import { ElMessageBox } from "element-plus";
import { getErrorMessage } from "../../services/adminApi";
import { handleApiError } from "../useSession";

/** 管理端异步任务公共骨架：置 loading、清 error，catch 先记录文案再走统一错误处理，finally 复位 loading。 */
export async function runAdminTask(
  loading: Ref<boolean>,
  errorPrefix: string,
  task: () => Promise<void>,
  error?: Ref<string>,
): Promise<void> {
  loading.value = true;
  if (error) error.value = "";
  try {
    await task();
  } catch (taskError) {
    if (error) error.value = getErrorMessage(taskError);
    handleApiError(errorPrefix, taskError);
  } finally {
    loading.value = false;
  }
}

/** 危险操作确认：取消/关闭弹窗时静默返回，其余异常按统一 API 错误处理上报。 */
export async function confirmDangerAction(
  message: string,
  title: string,
  confirmButtonText: string,
  errorPrefix: string,
  action: () => Promise<void>,
  type: "warning" | "info" = "warning",
): Promise<void> {
  try {
    await ElMessageBox.confirm(message, title, {
      confirmButtonText,
      cancelButtonText: "取消",
      type,
    });
    await action();
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      handleApiError(errorPrefix, error);
  }
}

/** 分页总页数：总数不足一页（含 0）时仍保持 1 页。 */
export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}
