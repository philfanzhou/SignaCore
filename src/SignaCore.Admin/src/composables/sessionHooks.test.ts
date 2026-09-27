import { expect, it, vi } from 'vitest'
import { loadAllDomains, registerSessionHooks, resetAllDomains } from './sessionHooks'

it('invalidates pending domain loads before a later session can render', async () => {
  let finish!: () => void
  const pending = new Promise<void>((resolve) => { finish = resolve })
  const rendered: string[] = []
  const reset = vi.fn()
  registerSessionHooks({
    reset,
    load: async (isCurrent) => {
      await pending
      if (isCurrent()) rendered.push('old data')
    },
  })

  const oldLoad = loadAllDomains()
  resetAllDomains()
  finish()
  await oldLoad
  expect(reset).toHaveBeenCalled()
  expect(rendered).toEqual([])
})
