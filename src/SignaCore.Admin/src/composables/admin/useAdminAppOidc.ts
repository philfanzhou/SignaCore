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
 * Interactive OIDC client configuration calls the four existing management endpoints.
 * Validation follows the server OidcClientConfigurationValidator; its rejection messages are
 * shown verbatim to the administrator.
 *
 * - Redirect URIs and the claims callback (AdminApp.callbackUrl) are independent registrations.
 *   Neither is copied, prefilled, or written into the other.
 * - Public clients can explicitly enable Code flow. Explicit Public refresh also requires an active,
 *   secretless Code client, PerApplication audience, offline_access, and a session maximum age
 *   between 1 and 43200 seconds, as validated by the server.
 */

/** Show interactive configuration as disabled until the server values are loaded. */
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
/** Display the server 400 message verbatim. */
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

  /** Cancel editing by restoring the server values and clearing unsaved drafts. */
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
      // Show the server rejection verbatim and restore the loaded server values.
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
    // Trim surrounding whitespace only; leave URI normalization to the server.
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
