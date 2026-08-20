import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AdminApp } from '../services/adminApi'
import { formatTtl, getInitials, normalizeTtlValue } from './format'

function app(overrides: Partial<AdminApp>): AdminApp {
  return {
    appId: 'orders',
    appName: 'Orders',
    callbackUrl: 'https://orders.example.test/callback',
    callbackExpiresAt: null,
    isActive: true,
    createdAt: 0,
    ldapLoginMode: 'Disabled',
    smsLoginMode: 'Disabled',
    smsProfileKey: null,
    wechatLoginMode: 'Disabled',
    audienceMode: 'Shared',
    audience: 'SignaCore.Services',
    ...overrides,
  }
}

afterEach(() => vi.useRealTimers())

describe('normalizeTtlValue', () => {
  it.each([
    [24, 24],
    ['12.9', 12],
    ['', 1],
    ['not-a-number', 1],
    [0, 1],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeTtlValue(input)).toBe(expected)
  })
})

describe('formatTtl', () => {
  it('does not describe a TTL when no callback is configured', () => {
    expect(formatTtl(app({ callbackUrl: '' }))).toBe('-')
  })

  it('distinguishes a non-expiring callback from a missing callback', () => {
    expect(formatTtl(app({ callbackExpiresAt: null }))).not.toBe('-')
  })

  it('rounds a partial remaining hour up for display', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-08-20T00:00:00Z'))

    const text = formatTtl(app({ callbackExpiresAt: Date.now() / 1000 + 90 * 60 }))

    expect(text).toContain('2')
  })
})

describe('getInitials', () => {
  it('uses at most two uppercase characters and has a fallback', () => {
    expect(getInitials('alice')).toBe('AL')
    expect(getInitials('')).toBe('A')
  })
})
