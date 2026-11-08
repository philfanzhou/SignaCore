import { describe, expect, it } from 'vitest'
import { formatDate, getInitials } from './format'

describe('formatDate', () => {
  it('renders a missing value as a dash and keeps epoch zero', () => {
    expect(formatDate(null)).toBe('-')
    expect(formatDate(undefined)).toBe('-')
    expect(formatDate(0)).not.toBe('-')
  })

  it('normalizes second-based timestamps', () => {
    const fromSeconds = formatDate(1_800_000_000)
    const fromMilliseconds = formatDate(1_800_000_000_000)
    expect(fromSeconds).toBe(fromMilliseconds)
  })
})

describe('getInitials', () => {
  it('uses at most two uppercase characters and has a fallback', () => {
    expect(getInitials('alice')).toBe('AL')
    expect(getInitials('')).toBe('A')
  })
})
