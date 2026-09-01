import { computed, reactive, ref, type Ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminClient } from "../../services/apiClient";
import {
  getErrorMessage,
  type AdminApp,
  type AdminAppOidc,
  type AdminAppRedirectUri,
} from "../../services/adminApi";
import { handleApiError } from "../useSession";
import { notify } from "./useAdminFeedback";

/**
 * 交互式 OIDC 客户端配置。
 *
 * 本模块只消费管理 API 已有的四个端点，不自行放宽或收紧任何规则：服务端的
 * OidcClientConfigurationValidator 是唯一校验权威，被拒绝的原因原样呈现给管理员。
 *
 * 两条固定不变量：
 * - Redirect URI 与 claims callback（AdminApp.callbackUrl）是两套独立注册，任何一侧都不会
 *   被复制、预填或写入另一侧。
 * - Public 客户端保持 fail closed：界面把它呈现为不可启用，也不提供提交 Public 的路径。
 */

/** 未配置过交互式 OIDC 的应用在服务端就是这套值，界面按「未启用」展示而不是空白。 */
const emptyOidc: AdminAppOidc = {
  appId: "",
  clientType: "Confidential",
  allowAuthorizationCode: false,
  allowedScopes: [],
  allowRefreshToken: false,
  identitySessionMaxAgeSeconds: null,
  audienceMode: "Shared",
  redirectUris: [],
  postLogoutRedirectUris: [],
};

const oidcConfig = ref<AdminAppOidc>({ ...emptyOidc });
const oidcLoading = ref(false);
const oidcSaving = ref(false);
/** 服务端 400 的原文，逐字呈现，不做改写或归纳。 */
const oidcError = ref("");
const oidcPolicyForm = reactive({
  allowAuthorizationCode: false,
  allowedScopes: "",
  allowRefreshToken: false,
  identitySessionMaxAgeSeconds: "" as number | "",
});
const redirectUriDraft = ref("");
const postLogoutUriDraft = ref("");

const isPublicClient = computed(() => oidcConfig.value.clientType === "Public");
const interactiveEnabled = computed(
  () => oidcConfig.value.allowAuthorizationCode,
);

function syncPolicyForm(config: AdminAppOidc) {
  Object.assign(oidcPolicyForm, {
    allowAuthorizationCode: config.allowAuthorizationCode,
    allowedScopes: config.allowedScopes.join(" "),
    allowRefreshToken: config.allowRefreshToken,
    identitySessionMaxAgeSeconds: config.identitySessionMaxAgeSeconds ?? "",
  });
}

export function useAdminAppOidc(selectedApp: Ref<AdminApp | null>) {
  async function loadOidc(appId: string) {
    oidcLoading.value = true;
    oidcError.value = "";
    try {
      const config = await adminClient.getAppOidc(appId);
      oidcConfig.value = config;
      syncPolicyForm(config);
    } catch (error) {
      handleApiError("加载交互式 OIDC 配置失败", error);
      oidcError.value = getErrorMessage(error);
    } finally {
      oidcLoading.value = false;
    }
  }

  /** 取消编辑：本地状态回到服务端返回值，不残留未提交修改。 */
  function resetPolicyForm() {
    syncPolicyForm(oidcConfig.value);
    redirectUriDraft.value = "";
    postLogoutUriDraft.value = "";
    oidcError.value = "";
  }

  async function reloadOidc() {
    if (!selectedApp.value) return;
    await loadOidc(selectedApp.value.appId);
  }

  async function saveOidcPolicy() {
    if (!selectedApp.value) return;
    // Public 客户端由 #81 开放；在此之前界面不提供任何提交 Public 的路径，也不去试探服务端。
    if (isPublicClient.value) {
      return notify("Public 客户端保持保留状态，当前无法从控制台启用。");
    }

    const maxAge = oidcPolicyForm.identitySessionMaxAgeSeconds;
    oidcSaving.value = true;
    oidcError.value = "";
    try {
      await adminClient.updateOidcPolicy(selectedApp.value.appId, {
        clientType: oidcConfig.value.clientType,
        allowAuthorizationCode: oidcPolicyForm.allowAuthorizationCode,
        allowedScopes: oidcPolicyForm.allowedScopes
          .split(/[\s,]+/)
          .filter((scope) => scope.length > 0),
        allowRefreshToken: oidcPolicyForm.allowRefreshToken,
        identitySessionMaxAgeSeconds: maxAge === "" ? null : Number(maxAge),
      });
      await loadOidc(selectedApp.value.appId);
      notify("交互式 OIDC 策略已保存");
    } catch (error) {
      // 服务端拒绝：原文呈现，并把本地状态退回到服务端当前值，不留下半提交的界面。
      oidcError.value = getErrorMessage(error);
      handleApiError("保存交互式 OIDC 策略失败", error);
      syncPolicyForm(oidcConfig.value);
    } finally {
      oidcSaving.value = false;
    }
  }

  async function addRedirectUri(kind: AdminAppRedirectUri["kind"]) {
    if (!selectedApp.value) return;
    const draft = kind === "Redirect" ? redirectUriDraft : postLogoutUriDraft;
    // 只去掉首尾空白：注册值按管理员输入的精确形式比较，界面不做任何规范化。
    const uri = draft.value.trim();
    if (!uri) {
      return notify(
        kind === "Redirect"
          ? "请输入要注册的 Redirect URI"
          : "请输入要注册的 Post Logout URI",
      );
    }

    oidcSaving.value = true;
    oidcError.value = "";
    try {
      await adminClient.addOidcRedirectUris(selectedApp.value.appId, kind, [
        uri,
      ]);
      draft.value = "";
      await loadOidc(selectedApp.value.appId);
      notify(kind === "Redirect" ? "Redirect URI 已注册" : "Post Logout URI 已注册");
    } catch (error) {
      oidcError.value = getErrorMessage(error);
      handleApiError("注册 URI 失败", error);
    } finally {
      oidcSaving.value = false;
    }
  }

  async function removeRedirectUri(registration: AdminAppRedirectUri) {
    if (!selectedApp.value) return;
    try {
      await ElMessageBox.confirm(
        "移除后，使用该地址的授权请求会被拒绝。",
        "移除 URI 注册",
        {
          confirmButtonText: "移除",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
    } catch (error) {
      if (error !== "cancel" && error !== "close")
        handleApiError("移除 URI 注册失败", error);
      return;
    }

    oidcSaving.value = true;
    oidcError.value = "";
    try {
      await adminClient.removeOidcRedirectUri(
        selectedApp.value.appId,
        registration.id,
      );
      await loadOidc(selectedApp.value.appId);
      notify("URI 注册已移除");
    } catch (error) {
      oidcError.value = getErrorMessage(error);
      handleApiError("移除 URI 注册失败", error);
    } finally {
      oidcSaving.value = false;
    }
  }

  function clearOidc() {
    oidcConfig.value = { ...emptyOidc };
    syncPolicyForm(oidcConfig.value);
    redirectUriDraft.value = "";
    postLogoutUriDraft.value = "";
    oidcError.value = "";
  }

  return {
    oidcConfig,
    oidcLoading,
    oidcSaving,
    oidcError,
    oidcPolicyForm,
    redirectUriDraft,
    postLogoutUriDraft,
    isPublicClient,
    interactiveEnabled,
    loadOidc,
    reloadOidc,
    resetPolicyForm,
    saveOidcPolicy,
    addRedirectUri,
    removeRedirectUri,
    clearOidc,
  };
}
