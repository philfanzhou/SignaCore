import { reactive, ref, type Ref } from "vue";
import { adminClient } from "../../services/apiClient";
import {
  type AdminApp,
  type AdminExchangeTrust,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { notify } from "./useAdminFeedback";
import { confirmDangerAction, runAdminTask } from "./adminTask";

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
    await runAdminTask(accessLoading, "加载应用登录许可列表失败", async () => {
      const [sms, wechat, ldap] = await Promise.all([
        adminClient.getAppSmsUsers(appId),
        adminClient.getAppWechatUsers(appId),
        adminClient.getAppLdapUsers(appId),
      ]);
      appSmsUsers.value = sms;
      appWechatUsers.value = wechat;
      appLdapUsers.value = ldap;
    });
  }

  async function loadAppDetails(appId: string) {
    await runAdminTask(appDetailLoading, "加载应用策略失败", async () => {
      void loadAppAccess(appId);
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
    });
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
      notify("短信登录许可已添加");
    } catch (error) {
      handleApiError("添加短信登录许可失败", error);
    }
  }

  async function revokeSmsUser(loginId: string) {
    if (!selectedApp.value) return;
    const app = selectedApp.value;
    await confirmDangerAction(
      "撤销后该手机号不能通过当前应用的短信登录。",
      "撤销短信登录许可",
      "撤销",
      "撤销短信登录许可失败",
      async () => {
        await adminClient.revokeAppSmsUser(app.appId, loginId);
        await loadAppAccess(app.appId);
        notify("短信登录许可已撤销");
      },
    );
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
      notify("LDAP 登录许可已添加");
    } catch (error) {
      handleApiError("添加 LDAP 登录许可失败", error);
    }
  }

  async function revokeLdapUser(credentialId: string) {
    if (!selectedApp.value) return;
    const app = selectedApp.value;
    await confirmDangerAction(
      "撤销后该域账号不能通过当前应用的 LDAP 登录。",
      "撤销 LDAP 登录许可",
      "撤销",
      "撤销 LDAP 登录许可失败",
      async () => {
        await adminClient.revokeAppLdapUser(app.appId, credentialId);
        await loadAppAccess(app.appId);
        notify("LDAP 登录许可已撤销");
      },
    );
  }

  async function revokeWechatUser(loginId: string) {
    if (!selectedApp.value) return;
    const app = selectedApp.value;
    await confirmDangerAction(
      "撤销后该微信账号不能通过当前应用登录，后续需要管理员手动恢复。",
      "撤销微信登录许可",
      "撤销",
      "撤销微信登录许可失败",
      async () => {
        await adminClient.revokeAppWechatUser(app.appId, loginId);
        await loadAppAccess(app.appId);
        notify("微信登录许可已撤销");
      },
    );
  }

  async function restoreWechatUser(loginId: string) {
    if (!selectedApp.value) return;
    try {
      await adminClient.restoreAppWechatUser(selectedApp.value.appId, loginId);
      await loadAppAccess(selectedApp.value.appId);
      notify("微信登录许可已恢复");
    } catch (error) {
      handleApiError("恢复微信登录许可失败", error);
    }
  }

  async function addTrust() {
    if (!selectedApp.value || !trustSourceAppId.value.trim())
      return notify("请输入来源 App ID");
    const app = selectedApp.value;
    await confirmDangerAction(
      "添加信任后，可使用来源应用签发的有效刷新令牌为同一账号创建当前应用会话，仍须通过账号状态、令牌来源和当前应用登录许可等检查。业务权限由当前应用的回调和授权规则决定。",
      "添加跨应用刷新信任",
      "确认添加",
      "添加跨应用刷新信任失败",
      async () => {
        await adminClient.addExchangeTrust(
          app.appId,
          trustSourceAppId.value.trim(),
        );
        trustSourceAppId.value = "";
        appTrusts.value = await adminClient.getExchangeTrusts(app.appId);
        notify("跨应用刷新信任已添加");
      },
    );
  }

  async function removeTrust(trust: AdminExchangeTrust) {
    if (!selectedApp.value) return;
    const app = selectedApp.value;
    await confirmDangerAction(
      "撤销后不再接受该来源应用的刷新令牌，但通过该信任已创建的当前应用会话不会因此结束。",
      "撤销跨应用刷新信任",
      "撤销",
      "撤销跨应用刷新信任失败",
      async () => {
        await adminClient.removeExchangeTrust(app.appId, trust.sourceAppId);
        appTrusts.value = await adminClient.getExchangeTrusts(app.appId);
        notify("跨应用刷新信任已撤销");
      },
    );
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
    revokeWechatUser,
    restoreWechatUser,
    addTrust,
    removeTrust,
    clearAccess,
  };
}
