import type { Ref } from "vue";
import { ElMessageBox } from "element-plus";
import { getErrorMessage } from "../../services/adminApi";
import { handleApiError } from "../useSession";

/**
 * Shared skeleton for admin async tasks: mark the bound `loading` ref, clear the optional
 * `error` text, run `task`, record its failure text and hand the error to the shared API
 * error handler, then reset `loading` in `finally`.
 */
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

/**
 * Danger-action confirmation: ask through `ElMessageBox.confirm` with the supplied copy, run
 * `action` only after the administrator confirms, and treat the box's `cancel`/`close`
 * rejections as a silent no-op. Any other failure goes to the shared API error handler with
 * `errorPrefix`; `type` selects the icon variant and defaults to `warning`.
 */
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

/** Total page count, clamped to at least 1 so an empty list still renders one page. */
export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}
