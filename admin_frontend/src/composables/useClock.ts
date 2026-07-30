import { ref } from 'vue'

const clockText = ref('')
let clockTimer: number | undefined

function tickClock() {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  clockText.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function startClock() {
  tickClock()
  clockTimer = window.setInterval(tickClock, 1000)
}

function stopClock() {
  if (clockTimer) {
    window.clearInterval(clockTimer)
    clockTimer = undefined
  }
}

export function useClock() {
  return {
    clockText,
    startClock,
    stopClock,
  }
}
