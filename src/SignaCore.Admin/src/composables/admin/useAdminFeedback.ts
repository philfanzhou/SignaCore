import { ref } from "vue";

const toast = ref("");
let toastTimer: number | undefined;

export function notify(message: string) {
  toast.value = message;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toast.value = "";
  }, 3600);
}

export function useAdminFeedback() {
  return { toast, notify };
}
