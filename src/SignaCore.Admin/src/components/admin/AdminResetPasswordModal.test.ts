import { createSSRApp, ref, reactive } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { beforeEach, expect, it, vi } from 'vitest'
import type { AdminUser } from '../../services/adminApi'

const state = {
  selectedUser: ref<Partial<AdminUser> | null>(null), userDrawerOpen: ref(true), userDrawerTab: ref('profile'),
  userHistory: ref([]), userHistoryTotal: ref(0), userHistoryLoading: ref(false),
  userSessions: ref([]), userSessionsTotal: ref(0), userSessionsLoading: ref(false), userSessionRevokingId: ref(''),
  userMeta: reactive({ nickname: '', remark: '' }),
  updateUserMeta: vi.fn(), toggleUser: vi.fn(), closeUserDrawer: vi.fn(), loadUserHistory: vi.fn(),
  loadUserSessions: vi.fn(), revokeUserSession: vi.fn(), openResetPassword: vi.fn(), closeResetPassword: vi.fn(),
  resetUserPassword: vi.fn(), resetPasswordTarget: ref<{ userId: string; username: string } | null>(null),
  resetPasswordForm: reactive({ newPassword: '', confirmation: '' }), resetPasswordSaving: ref(false), resetPasswordError: ref(''),
}
vi.mock('../../composables/admin/useAdminUsers', () => ({ useAdminUsers: () => state }))
import AdminUserDrawer from './AdminUserDrawer.vue'
import AdminResetPasswordModal from './AdminResetPasswordModal.vue'

beforeEach(() => {
  state.selectedUser.value = { userId: 'account-1', username: 'target-user', hasPassword: true, createdAt: 1, isActive: true }
  state.resetPasswordTarget.value = null
  state.resetPasswordSaving.value = false
  state.resetPasswordError.value = ''
})
it('renders the reset entry only for password accounts and leaves account editing available', async () => {
  const html = await renderToString(createSSRApp(AdminUserDrawer))
  expect(html).toContain('Reset password')
  expect(html).toContain('inline-save')
  state.selectedUser.value!.hasPassword = false
  expect(await renderToString(createSSRApp(AdminUserDrawer))).not.toContain('Reset password')
})
it('renders the captured username, two password fields, policy bypass, error and disabled submission', async () => {
  state.resetPasswordTarget.value = { userId: 'captured-account', username: 'captured-user' }
  state.resetPasswordSaving.value = true
  state.resetPasswordError.value = 'Request unavailable.'
  const html = await renderToString(createSSRApp(AdminResetPasswordModal))
  expect(html).toContain('captured-user')
  expect(html.match(/type="password"/g)).toHaveLength(2)
  expect(html).toContain('Administrator resets bypass password length and complexity requirements.')
  expect(html).toContain('The password cannot be blank.')
  expect(html).not.toContain('At least 8 characters')
  expect(html).not.toMatch(/minlength=|pattern=/)
  expect(html).toContain('role="alert"')
  expect(html).toContain('Request unavailable.')
  expect(html).toMatch(/type="submit"[^>]*disabled/)
  expect(html).toContain('Cancel')
})
