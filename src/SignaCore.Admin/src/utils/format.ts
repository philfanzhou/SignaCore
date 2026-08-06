import type { AdminApp } from '../services/adminApi'

/* TTL 输入钳制：至少 1，非法输入回退 1（对齐样稿 Math.max(1, parseInt(...||'1'))；API 换算规则不变）
   v-model.number 清空输入时运行时会得到 ''（string），故签名放宽为 number | string */
export function normalizeTtlValue(value: number | string): number {
  const n = Math.floor(Number(value))
  return Number.isFinite(n) && n >= 1 ? n : 1
}

export function formatDate(dateVal: string | number | null | undefined): string {
  if (!dateVal && dateVal !== 0) return '-'
  try {
    let ts: number
    if (typeof dateVal === 'number') {
      ts = dateVal
    } else {
      const parsed = Number(dateVal)
      ts = isNaN(parsed) ? new Date(dateVal).getTime() / 1000 : parsed
    }
    if (ts < 10000000000) ts *= 1000
    const d = new Date(ts)
    const p = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
  } catch {
    return String(dateVal)
  }
}

export function formatTtl(app: AdminApp): string {
  if (!app.callbackUrl) return '-'
  if (!app.callbackExpiresAt) return '永不过期'
  const remainingSec = Math.max(0, Math.floor(app.callbackExpiresAt - Date.now() / 1000))
  if (remainingSec >= 86400 && remainingSec % 86400 === 0) return `${remainingSec / 86400} 天`
  return `${Math.max(1, Math.ceil(remainingSec / 3600))} 小时`
}

export function getInitials(name: string): string {
  return name ? name.substring(0, 2).toUpperCase() : 'A'
}
