import { computed, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { adminClient } from '../services/apiClient'
import { getErrorMessage, type AdminSetting } from '../services/adminApi'
import { registerSessionHooks } from './sessionHooks'

/**
 * Global settings live in the business database. The console edits a draft and submits only the keys
 * that actually changed, so an untouched secret is never round-tripped through the browser.
 */

const settings = ref<AdminSetting[]>([])
const loading = ref(false)
const saving = ref(false)
const configurationVersion = ref(0)
const runningConfigurationVersion = ref(0)
const restartPending = ref(false)

/** Key -> edited value. Absent means untouched. */
const draft = reactive<Record<string, string>>({})

/** Settings are grouped by their configuration prefix, which is how operators think about them. */
const groups = computed(() => {
  const byPrefix = new Map<string, AdminSetting[]>()
  for (const setting of settings.value) {
    const prefix = setting.key.split(':')[0]
    const bucket = byPrefix.get(prefix)
    if (bucket) {
      bucket.push(setting)
    } else {
      byPrefix.set(prefix, [setting])
    }
  }
  return [...byPrefix.entries()].map(([prefix, items]) => ({ prefix, items }))
})

const hasChanges = computed(() => Object.keys(draft).length > 0)

function resetDraft() {
  for (const key of Object.keys(draft)) {
    delete draft[key]
  }
}

export function editedValue(setting: AdminSetting): string {
  if (setting.key in draft) {
    return draft[setting.key]
  }
  // A secret's stored value is never sent to the browser, so the field starts blank and an empty
  // submission means "leave unchanged" rather than "clear it".
  return setting.isSecret ? '' : (setting.value ?? '')
}

export function setEditedValue(setting: AdminSetting, value: string) {
  const original = setting.isSecret ? '' : (setting.value ?? '')
  if (value === original) {
    delete draft[setting.key]
    return
  }
  draft[setting.key] = value
}

export async function loadSettings() {
  loading.value = true
  try {
    const result = await adminClient.getSettings()
    settings.value = result.items
    configurationVersion.value = result.configurationVersion
    runningConfigurationVersion.value = result.runningConfigurationVersion
    restartPending.value = result.restartPending
    resetDraft()
  } catch (error) {
    ElMessage.error(`加载配置失败: ${getErrorMessage(error)}`)
  } finally {
    loading.value = false
  }
}

export async function saveSettings() {
  if (!hasChanges.value) return

  saving.value = true
  try {
    const result = await adminClient.updateSettings({ ...draft })
    ElMessage.success(result.message)
    await loadSettings()
    restartPending.value = result.restartRequired
  } catch (error) {
    ElMessage.error(`保存配置失败: ${getErrorMessage(error)}`)
  } finally {
    saving.value = false
  }
}

export function discardChanges() {
  resetDraft()
}

registerSessionHooks({
  load: loadSettings,
  reset: () => {
    settings.value = []
    configurationVersion.value = 0
    runningConfigurationVersion.value = 0
    restartPending.value = false
    resetDraft()
  },
})

export function useSettings() {
  return {
    settings,
    groups,
    loading,
    saving,
    hasChanges,
    configurationVersion,
    runningConfigurationVersion,
    restartPending,
  }
}
