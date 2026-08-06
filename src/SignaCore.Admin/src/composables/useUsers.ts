import { computed, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { type AdminUser } from '../services/adminApi'
import { adminClient } from '../services/apiClient'
import { handleApiError } from './useSession'
import { registerSessionHooks } from './sessionHooks'

const loadingUsers = ref(false)
const creatingUser = ref(false)
const creatingPhoneUser = ref(false)
const users = ref<AdminUser[]>([])
const userTotal = ref(0)
const page = ref(1)
const pageSize = ref(20)

const showCreateUserDialog = ref(false)
const showCreatePhoneUserDialog = ref(false)

const userFilters = reactive({
  username: '',
  phone: '',
})

/* 用户列表 chip 筛选（前端筛选当前页数据，不影响 API 参数） */
const userStatusFilter = ref<'all' | 'active' | 'disabled'>('all')
const filteredUsers = computed(() => {
  if (userStatusFilter.value === 'active') return users.value.filter(u => u.isActive)
  if (userStatusFilter.value === 'disabled') return users.value.filter(u => !u.isActive)
  return users.value
})
const activeUsersInPage = computed(() => users.value.filter(u => u.isActive).length)
const disabledUsersInPage = computed(() => users.value.filter(u => !u.isActive).length)

const totalPages = computed(() => Math.ceil(userTotal.value / pageSize.value))
const pageNumbers = computed(() => {
  const total = totalPages.value
  if (total <= 0) return []
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
  const pages: number[] = []
  const current = page.value
  const start = Math.max(1, current - 2)
  const end = Math.min(total, current + 2)
  for (let i = start; i <= end; i++) pages.push(i)
  return pages
})

const createUserForm = reactive({
  username: '',
  password: '',
  remark: '',
})

const createPhoneUserForm = reactive({
  phone: '',
  remark: '',
})

/* ============ 抽屉与模态框状态（展示层新增，不调用 API） ============ */
/* visible 控制挂载、open 控制 .open 类，拆分以驱动进出场过渡（对齐样稿 double-rAF 模式） */
const userDrawerVisible = ref(false)
const userDrawerOpen = ref(false)
const userDrawerUser = ref<AdminUser | null>(null)
const userDrawerTab = ref<'info'>('info')
let userDrawerTimer: number | undefined

const editRemarkOpen = ref(false)
const editRemarkTarget = ref<AdminUser | null>(null)
const editRemarkValue = ref('')

function resetCreateUserForm() {
  createUserForm.username = ''
  createUserForm.password = ''
  createUserForm.remark = ''
}

function resetCreatePhoneUserForm() {
  createPhoneUserForm.phone = ''
  createPhoneUserForm.remark = ''
}

function openCreateUserDialog() {
  resetCreateUserForm()
  showCreateUserDialog.value = true
}

function openCreatePhoneUserDialog() {
  resetCreatePhoneUserForm()
  showCreatePhoneUserDialog.value = true
}

async function loadUsers() {
  loadingUsers.value = true
  try {
    const result = await adminClient.getUsers({
      username: userFilters.username || undefined,
      phone: userFilters.phone || undefined,
      page: page.value,
      pageSize: pageSize.value,
    })
    users.value = result.items
    userTotal.value = result.total
    // keep the open user drawer in sync with the refreshed list
    const drawerUser = userDrawerUser.value
    if (drawerUser) {
      const fresh = result.items.find((item) => item.userId === drawerUser.userId)
      if (fresh) userDrawerUser.value = fresh
    }
  } catch (error) {
    handleApiError('加载用户列表失败', error)
  } finally {
    loadingUsers.value = false
  }
}

function handleSearch() {
  page.value = 1
  loadUsers()
}

function handlePageChange(newPage: number) {
  page.value = newPage
  loadUsers()
}

async function handleCreateUser() {
  if (!createUserForm.username || !createUserForm.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }

  creatingUser.value = true
  try {
    await adminClient.createUser({
      username: createUserForm.username,
      password: createUserForm.password,
      remark: createUserForm.remark || undefined,
    })
    ElMessage.success('用户创建成功')
    showCreateUserDialog.value = false
    resetCreateUserForm()
    await loadUsers()
  } catch (error) {
    handleApiError('创建用户失败', error)
  } finally {
    creatingUser.value = false
  }
}

async function handleCreatePhoneUser() {
  if (!createPhoneUserForm.phone) {
    ElMessage.warning('请输入手机号')
    return
  }

  creatingPhoneUser.value = true
  try {
    await adminClient.createPhoneUser({
      phone: createPhoneUserForm.phone,
      remark: createPhoneUserForm.remark || undefined,
    })
    ElMessage.success('手机账号创建成功')
    showCreatePhoneUserDialog.value = false
    resetCreatePhoneUserForm()
    await loadUsers()
  } catch (error) {
    handleApiError('创建手机账号失败', error)
  } finally {
    creatingPhoneUser.value = false
  }
}

async function handleToggleUserStatus(user: AdminUser, event?: Event): Promise<boolean> {
  const action = user.isActive ? '禁用' : '启用'
  const name = user.username || user.displayName || user.userId
  const revertSwitch = () => {
    if (event?.target instanceof HTMLInputElement) {
      event.target.checked = user.isActive
    }
  }
  try {
    await ElMessageBox.confirm(
      `确定要${action}用户 "${name}" 吗？`,
      '确认操作',
      { confirmButtonText: '确认', cancelButtonText: '取消', type: 'warning' }
    )
  } catch {
    revertSwitch()
    return false
  }

  try {
    await adminClient.updateUserStatus(user.userId, !user.isActive)
    ElMessage.success(`用户已${action}`)
    await loadUsers()
    return true
  } catch (error) {
    revertSwitch()
    handleApiError(`${action}用户失败`, error)
    return false
  }
}

function openUserDrawer(user: AdminUser) {
  if (userDrawerTimer) { window.clearTimeout(userDrawerTimer); userDrawerTimer = undefined }
  userDrawerUser.value = user
  userDrawerTab.value = 'info'
  userDrawerVisible.value = true
  requestAnimationFrame(() => requestAnimationFrame(() => {
    userDrawerOpen.value = true
  }))
}

function closeUserDrawer() {
  if (!userDrawerVisible.value) return
  userDrawerOpen.value = false
  if (userDrawerTimer) window.clearTimeout(userDrawerTimer)
  userDrawerTimer = window.setTimeout(() => {
    userDrawerVisible.value = false
    userDrawerUser.value = null
    userDrawerTimer = undefined
  }, 300)
}

/* drawer 底部启用/禁用按钮：成功后按样稿行为关闭 drawer */
async function toggleDrawerUserStatus() {
  const user = userDrawerUser.value
  if (!user) return
  const ok = await handleToggleUserStatus(user)
  if (ok) closeUserDrawer()
}

function openEditRemarkModal(user: AdminUser) {
  editRemarkTarget.value = user
  editRemarkValue.value = user.remark || ''
  editRemarkOpen.value = true
}

async function saveEditRemark() {
  if (!editRemarkTarget.value) return
  const val = editRemarkValue.value
  if (val.length > 200) {
    ElMessage.warning('备注不能超过200个字符')
    return
  }
  try {
    await adminClient.updateUserRemark(editRemarkTarget.value.userId, val)
    ElMessage.success('备注更新成功')
    editRemarkOpen.value = false
    editRemarkTarget.value = null
    await loadUsers()
  } catch (error) {
    handleApiError('更新备注失败', error)
  }
}

/* 会话重置时清理本域状态（对应原 resetAdminState 的用户域字段） */
function resetUsersState() {
  users.value = []
  userTotal.value = 0
  page.value = 1
  userStatusFilter.value = 'all'
  if (userDrawerTimer) { window.clearTimeout(userDrawerTimer); userDrawerTimer = undefined }
  userDrawerOpen.value = false
  userDrawerVisible.value = false
  userDrawerUser.value = null
  editRemarkOpen.value = false
  showCreateUserDialog.value = false
  showCreatePhoneUserDialog.value = false
}

registerSessionHooks({ reset: resetUsersState, load: loadUsers })

export function disposeUsers() {
  if (userDrawerTimer) { window.clearTimeout(userDrawerTimer); userDrawerTimer = undefined }
}

export function useUsers() {
  return {
    loadingUsers,
    creatingUser,
    creatingPhoneUser,
    users,
    userTotal,
    page,
    pageSize,
    showCreateUserDialog,
    showCreatePhoneUserDialog,
    userFilters,
    userStatusFilter,
    filteredUsers,
    activeUsersInPage,
    disabledUsersInPage,
    totalPages,
    pageNumbers,
    createUserForm,
    createPhoneUserForm,
    userDrawerVisible,
    userDrawerOpen,
    userDrawerUser,
    userDrawerTab,
    editRemarkOpen,
    editRemarkTarget,
    editRemarkValue,
    resetCreateUserForm,
    resetCreatePhoneUserForm,
    openCreateUserDialog,
    openCreatePhoneUserDialog,
    loadUsers,
    handleSearch,
    handlePageChange,
    handleCreateUser,
    handleCreatePhoneUser,
    handleToggleUserStatus,
    openUserDrawer,
    closeUserDrawer,
    toggleDrawerUserStatus,
    openEditRemarkModal,
    saveEditRemark,
  }
}
