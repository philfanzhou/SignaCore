import { computed, reactive, ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminClient } from "../../services/apiClient";
import {
  getErrorMessage,
  type AdminLoginHistoryItem,
  type AdminUser,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { notify } from "./useAdminFeedback";

const users = ref<AdminUser[]>([]);
const userTotal = ref(0);
const userPage = ref(1);
const userPageSize = 12;
const userLoading = ref(false);
const userError = ref("");
const userFilters = reactive({
  username: "",
  phone: "",
  status: "all" as "all" | "active" | "disabled",
});
const selectedUser = ref<AdminUser | null>(null);
const userDrawerOpen = ref(false);
const userDrawerTab = ref<"profile" | "history">("profile");
const userHistory = ref<AdminLoginHistoryItem[]>([]);
const userHistoryTotal = ref(0);
const userHistoryLoading = ref(false);
const userMeta = reactive({ displayName: "", nickname: "", remark: "" });
const userMode = ref<"password" | "phone">("password");
const userModalOpen = ref(false);
const userSaving = ref(false);
const createUserForm = reactive({
  username: "",
  password: "",
  phone: "",
  displayName: "",
  nickname: "",
  remark: "",
});

const filteredUsers = computed(() => {
  if (userFilters.status === "active")
    return users.value.filter((user) => user.isActive);
  if (userFilters.status === "disabled")
    return users.value.filter((user) => !user.isActive);
  return users.value;
});
const userPages = computed(() =>
  Math.max(1, Math.ceil(userTotal.value / userPageSize)),
);

function resetUserForm() {
  Object.assign(createUserForm, {
    username: "",
    password: "",
    phone: "",
    displayName: "",
    nickname: "",
    remark: "",
  });
}

async function loadUsers() {
  userLoading.value = true;
  userError.value = "";
  try {
    const result = await adminClient.getUsers({
      username: userFilters.username.trim() || undefined,
      phone: userFilters.phone.trim() || undefined,
      page: userPage.value,
      pageSize: userPageSize,
    });
    users.value = result.items;
    userTotal.value = result.total;
    if (userPage.value > Math.max(1, Math.ceil(result.total / userPageSize)))
      userPage.value = 1;
    if (selectedUser.value)
      selectedUser.value =
        result.items.find(
          (item) => item.userId === selectedUser.value?.userId,
        ) ?? selectedUser.value;
  } catch (error) {
    userError.value = getErrorMessage(error);
    handleApiError("加载账户目录失败", error);
  } finally {
    userLoading.value = false;
  }
}

function searchUsers() {
  userPage.value = 1;
  void loadUsers();
}
function changeUserPage(page: number) {
  userPage.value = Math.min(Math.max(page, 1), userPages.value);
  void loadUsers();
}

async function saveUser() {
  if (
    userMode.value === "password" &&
    (!createUserForm.username.trim() || createUserForm.password.length < 8)
  )
    return notify("请输入用户名，并设置至少 8 位密码");
  if (
    userMode.value === "phone" &&
    !/^1[3-9]\d{9}$/.test(createUserForm.phone.trim())
  )
    return notify("请输入有效的中国大陆手机号");
  userSaving.value = true;
  try {
    if (userMode.value === "password") {
      await adminClient.createUser({
        username: createUserForm.username.trim(),
        password: createUserForm.password,
        displayName: createUserForm.displayName.trim() || undefined,
        nickname: createUserForm.nickname.trim() || undefined,
        remark: createUserForm.remark.trim() || undefined,
      });
    } else {
      await adminClient.createPhoneUser({
        phone: createUserForm.phone.trim(),
        displayName: createUserForm.displayName.trim() || undefined,
        nickname: createUserForm.nickname.trim() || undefined,
        remark: createUserForm.remark.trim() || undefined,
      });
    }
    userModalOpen.value = false;
    resetUserForm();
    notify("账户已创建");
    await loadUsers();
  } catch (error) {
    handleApiError("创建账户失败", error);
  } finally {
    userSaving.value = false;
  }
}

function openUser(user: AdminUser) {
  selectedUser.value = user;
  userDrawerTab.value = "profile";
  Object.assign(userMeta, {
    displayName: user.displayName || "",
    nickname: user.nickname || "",
    remark: user.remark || "",
  });
  userHistory.value = [];
  userHistoryTotal.value = 0;
  userDrawerOpen.value = true;
  void loadUserHistory();
}

async function loadUserHistory() {
  if (!selectedUser.value) return;
  userHistoryLoading.value = true;
  try {
    const result = await adminClient.getUserLoginHistory(
      selectedUser.value.userId,
      { page: 1, pageSize: 10 },
    );
    userHistory.value = result.items;
    userHistoryTotal.value = result.total;
  } catch (error) {
    handleApiError("加载登录历史失败", error);
  } finally {
    userHistoryLoading.value = false;
  }
}

async function updateUserMeta(field: "nickname" | "remark") {
  if (!selectedUser.value) return;
  try {
    if (field === "nickname")
      await adminClient.updateUserNickname(
        selectedUser.value.userId,
        userMeta.nickname.trim(),
      );
    else
      await adminClient.updateUserRemark(
        selectedUser.value.userId,
        userMeta.remark.trim(),
      );
    notify("账户资料已保存");
    await loadUsers();
  } catch (error) {
    handleApiError("保存账户资料失败", error);
  }
}

async function toggleUser(user: AdminUser) {
  const action = user.isActive ? "禁用" : "启用";
  try {
    await ElMessageBox.confirm(
      `确认${action}账户「${user.username || user.displayName || user.userId}」？`,
      `${action}账户`,
      {
        confirmButtonText: action,
        cancelButtonText: "取消",
        type: user.isActive ? "warning" : "info",
      },
    );
    await adminClient.updateUserStatus(user.userId, !user.isActive);
    notify(`账户已${action}`);
    await loadUsers();
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      handleApiError(`${action}账户失败`, error);
  }
}

function closeUserDrawer() {
  userDrawerOpen.value = false;
  selectedUser.value = null;
}

export function useAdminUsers() {
  return {
    users,
    userTotal,
    userPage,
    userLoading,
    userError,
    userFilters,
    filteredUsers,
    userPages,
    selectedUser,
    userDrawerOpen,
    userDrawerTab,
    userHistory,
    userHistoryTotal,
    userHistoryLoading,
    userMeta,
    userMode,
    userModalOpen,
    userSaving,
    createUserForm,
    resetUserForm,
    loadUsers,
    searchUsers,
    changeUserPage,
    saveUser,
    openUser,
    loadUserHistory,
    updateUserMeta,
    toggleUser,
    closeUserDrawer,
  };
}
