/* 会话钩子注册表（Layer 0，无依赖）：
   各域 composable 在模块顶层注册 reset/load，useSession 的 resetAdminState 与
   登录/会话恢复路径经注册表回到各域，避免 useSession → 域 的循环依赖。 */
export interface SessionHooks {
  reset: () => void
  load?: (isCurrent: () => boolean) => Promise<unknown> | void
}

const hooks: SessionHooks[] = []
let generation = 0

export function registerSessionHooks(h: SessionHooks) {
  hooks.push(h)
}

export function resetAllDomains() {
  generation += 1
  hooks.forEach(h => h.reset())
}

export function loadAllDomains() {
  const loadGeneration = generation
  const isCurrent = () => generation === loadGeneration
  return Promise.all(hooks.map(h => h.load?.(isCurrent)))
}

export function refreshAll() {
  loadAllDomains()
}
