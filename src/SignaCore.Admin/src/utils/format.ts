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

export function getInitials(name: string): string {
  return name ? name.substring(0, 2).toUpperCase() : 'A'
}
