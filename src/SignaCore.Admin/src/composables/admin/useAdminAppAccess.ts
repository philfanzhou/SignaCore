import { reactive, ref, type Ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminClient } from "../../services/apiClient";
import {
  type AdminApp,
  type AdminExchangeTrust,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { notify } from "./useAdminFeedback";

const smsProfiles = ref<{ key: string; provider: string }[]>([]);
const ldapDirectories = ref<{ key: string; isDefault: boolean }[]>([]);
const appSmsUsers = ref<
  { loginId: string; phone: string; isActive: boolean; createdAt: number }[]
>([]);
const appWechatUsers = ref<
  { loginId: string; openId: string; isActive: boolean; createdAt: number }[]
>([]);
const appLdapUsers = ref<
  {
    credentialId: string;
    username: string;
    directoryKey: string;
    isActive: boolean;
    createdAt: number;
  }[]
>([]);
const appTrusts = ref<AdminExchangeTrust[]>([]);
const accessLoading = ref(false);
const appDetailLoading = ref(false);
const accessForm = reactive({ phone: "", directoryKey: "", username: "" });
const trustSourceAppId = ref("");

export function useAdminAppAccess(selectedApp: Ref<AdminApp | null>) {
  async function loadAppAccess(appId: string) {
    accessLoading.value = true;
    try {
      const [sms, wechat, ldap] = await Promise.all([
        adminClient.getAppSmsUsers(appId),
        adminClient.getAppWechatUsers(appId),
        adminClient.getAppLdapUsers(appId),
      ]);
      appSmsUsers.value = sms;
      appWechatUsers.value = wechat;
      appLdapUsers.value = ldap;
    } catch (error) {
      handleApiError("加载应用准入列表失败", error);
    } finally {
      accessLoading.value = false;
    }
  }

  async function loadAppDetails(appId: string) {
    appDetailLoading.value = true;
    void loadAppAccess(appId);
    try {
      const [trusts, profiles, directories] = await Promise.all([
        adminClient.getExchangeTrusts(appId),
        adminClient.getSmsProfiles(),
        adminClient.getLdapDirectories(),
      ]);
      appTrusts.value = trusts;
      smsProfiles.value = profiles;
      ldapDirectories.value = directories;
      accessForm.directoryKey =
        directories.find((item) => item.isDefault)?.key ??
        directories[0]?.key ??
        "";
    } catch (error) {
      handleApiError("加载应用策略失败", error);
    } finally {
      appDetailLoading.value = false;
    }
  }

  async function addSmsUser() {
    if (!selectedApp.value || !/^1[3-9]\d{9}$/.test(accessForm.phone.trim()))
      return notify("请输入有效手机号");
    try {
      await adminClient.addAppSmsUser(
        selectedApp.value.appId,
        accessForm.phone.trim(),
      );
      accessForm.phone = "";
      await loadAppAccess(selectedApp.value.appId);
      notify("短信准入已添加");
    } catch (error) {
      handleApiError("添加短信准入失败", error);
    }
  }

  async function revokeSmsUser(loginId: string) {
    if (!selectedApp.value) return;
    try {
      await ElMessageBox.confirm(
        "撤销后该手机号不能通过当前应用的短信登录。",
        "撤销短信准入",
        {
          confirmButtonText: "撤销",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
      await adminClient.revokeAppSmsUser(selectedApp.value.appId, loginId);
      await loadAppAccess(selectedApp.value.appId);
      notify("短信准入已撤销");
    } catch (error) {
      if (error !== "cancel" && error !== "close")
        handleApiError("撤销短信准入失败", error);
    }
  }

  async function addLdapUser() {
    if (
      !selectedApp.value ||
      !accessForm.directoryKey ||
      !accessForm.username.trim()
    )
      return notify("请选择目录并输入域账号");
    try {
      await adminClient.addAppLdapUser(
        selectedApp.value.appId,
        accessForm.directoryKey,
        accessForm.username.trim(),
      );
      accessForm.username = "";
      await loadAppAccess(selectedApp.value.appId);
      notify("LDAP 准入已添加");
    } catch (error) {
      handleApiError("添加 LDAP 准入失败", error);
    }
  }

  async function revokeLdapUser(credentialId: string) {
    if (!selectedApp.value) return;
    try {
      await ElMessageBox.confirm(
        "撤销后该域账号不能通过当前应用的 LDAP 登录。",
        "撤销 LDAP 准入",
        {
          confirmButtonText: "撤销",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
      await adminClient.revokeAppLdapUser(
        selectedApp.value.appId,
        credentialId,
      );
      await loadAppAccess(selectedApp.value.appId);
      notify("LDAP 准入已撤销");
    } catch (error) {
      if (error !== "cancel" && error !== "close")
        handleApiError("撤销 LDAP 准入失败", error);
    }
  }

  async function addTrust() {
    if (!selectedApp.value || !trustSourceAppId.value.trim())
      return notify("请输入来源 App ID");
    try {
      await ElMessageBox.confirm(
        "信任关系会让来源应用签发的 refresh token 可以换取当前应用会话，请确认权限边界已核对。",
        "添加换票信任",
        {
          confirmButtonText: "确认添加",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
      await adminClient.addExchangeTrust(
        selectedApp.value.appId,
        trustSourceAppId.value.trim(),
      );
      trustSourceAppId.value = "";
      appTrusts.value = await adminClient.getExchangeTrusts(
        selectedApp.value.appId,
      );
      notify("换票信任已添加");
    } catch (error) {
      if (error !== "cancel" && error !== "close")
        handleApiError("添加换票信任失败", error);
    }
  }

  async function removeTrust(trust: AdminExchangeTrust) {
    if (!selectedApp.value) return;
    try {
      await ElMessageBox.confirm(
        "撤销信任不会结束已经换出的当前应用会话。",
        "撤销换票信任",
        {
          confirmButtonText: "撤销",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
      await adminClient.removeExchangeTrust(
        selectedApp.value.appId,
        trust.sourceAppId,
      );
      appTrusts.value = await adminClient.getExchangeTrusts(
        selectedApp.value.appId,
      );
      notify("换票信任已撤销");
    } catch (error) {
      if (error !== "cancel" && error !== "close")
        handleApiError("撤销换票信任失败", error);
    }
  }

  function clearAccess() {
    appTrusts.value = [];
    appSmsUsers.value = [];
    appWechatUsers.value = [];
    appLdapUsers.value = [];
  }

  return {
    smsProfiles,
    ldapDirectories,
    appSmsUsers,
    appWechatUsers,
    appLdapUsers,
    appTrusts,
    accessLoading,
    appDetailLoading,
    accessForm,
    trustSourceAppId,
    loadAppAccess,
    loadAppDetails,
    addSmsUser,
    revokeSmsUser,
    addLdapUser,
    revokeLdapUser,
    addTrust,
    removeTrust,
    clearAccess,
  };
}
