import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  api: {
    getSettings: vi.fn(),
    updateSettings: vi.fn(),
  },
  success: vi.fn(),
  error: vi.fn(),
}))

vi.mock('../services/apiClient', () => ({ adminClient: mocks.api }))
vi.mock('element-plus', () => ({
  ElMessage: {
    success: mocks.success,
    error: mocks.error,
  },
}))

import type { AdminSetting } from '../services/adminApi'
import {
  discardChanges,
  editedValue,
  loadSettings,
  saveSettings,
  setEditedValue,
  useSettings,
} from './useSettings'

function setting(overrides: Partial<AdminSetting>): AdminSetting {
  return {
    key: 'Jwt:Audience',
    valueType: 'String',
    isSecret: false,
    value: 'SignaCore.Services',
    hasValue: true,
    restartRequired: true,
    updatedAt: null,
    updatedBy: null,
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  discardChanges()
})

describe('settings draft', () => {
  it('never starts a secret field with the stored value', () => {
    const secret = setting({
      key: 'WeChat:AppSecret',
      isSecret: true,
      value: null,
    })

    expect(editedValue(secret)).toBe('')
    setEditedValue(secret, 'replacement-secret')
    expect(editedValue(secret)).toBe('replacement-secret')
    expect(useSettings().hasChanges.value).toBe(true)
  })

  it('removes a key from the draft when it returns to its original value', () => {
    const audience = setting({})

    setEditedValue(audience, 'Orders')
    setEditedValue(audience, 'SignaCore.Services')

    expect(useSettings().hasChanges.value).toBe(false)
  })

  it('groups loaded settings by configuration prefix and clears stale edits', async () => {
    setEditedValue(setting({}), 'stale')
    mocks.api.getSettings.mockResolvedValue({
      configurationVersion: 4,
      runningConfigurationVersion: 3,
      restartPending: true,
      items: [
        setting({}),
        setting({ key: 'Jwt:Issuer', value: 'https://identity.example.test' }),
        setting({ key: 'Sms:MaxAttempts', valueType: 'Number', value: '5' }),
      ],
    })

    await loadSettings()

    const state = useSettings()
    expect(state.groups.value.map(group => group.prefix)).toEqual(['Jwt', 'Sms'])
    expect(state.configurationVersion.value).toBe(4)
    expect(state.restartPending.value).toBe(true)
    expect(state.hasChanges.value).toBe(false)
  })

  it('submits only changed keys and reloads the authoritative snapshot', async () => {
    const audience = setting({})
    mocks.api.updateSettings.mockResolvedValue({
      configurationVersion: 5,
      changedKeys: ['Jwt:Audience'],
      restartRequired: true,
      message: 'saved',
    })
    mocks.api.getSettings.mockResolvedValue({
      configurationVersion: 5,
      runningConfigurationVersion: 4,
      restartPending: true,
      items: [setting({ value: 'Orders' })],
    })
    setEditedValue(audience, 'Orders')

    await saveSettings()

    expect(mocks.api.updateSettings).toHaveBeenCalledWith({ 'Jwt:Audience': 'Orders' })
    expect(mocks.api.getSettings).toHaveBeenCalledOnce()
    expect(mocks.success).toHaveBeenCalledWith('saved')
    expect(useSettings().hasChanges.value).toBe(false)
  })
})
