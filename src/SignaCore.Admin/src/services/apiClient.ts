import { createAdminApiClient } from './adminApi'

/* 单一 axios 实例（原 App.vue 中的 const client = createAdminApiClient()） */
export const adminClient = createAdminApiClient()
