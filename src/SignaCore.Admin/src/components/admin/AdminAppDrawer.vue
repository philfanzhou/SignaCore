<script setup lang="ts">
import { useAdminApps } from "../../composables/admin/useAdminApps";
import { useAdminSecurity } from "../../composables/admin/useAdminSecurity";
import { formatDate } from "../../utils/format";

const {
  selectedApp,
  appDrawerOpen,
  appTab,
  appDetailLoading,
  appConfig,
  appSaving,
  smsProfiles,
  ldapDirectories,
  appSmsUsers,
  appWechatUsers,
  appLdapUsers,
  appTrusts,
  oidcConfig,
  oidcLoading,
  oidcSaving,
  oidcError,
  oidcPolicyForm,
  redirectUriDraft,
  postLogoutUriDraft,
  isPublicClient,
  saveOidcPolicy,
  addRedirectUri,
  removeRedirectUri,
  resetPolicyForm,
  accessForm,
  trustSourceAppId,
  appActionModal,
  deleteConfirmId,
  saveAppConfig,
  addSmsUser,
  revokeSmsUser,
  addLdapUser,
  revokeLdapUser,
  revokeWechatUser,
  restoreWechatUser,
  addTrust,
  removeTrust,
  closeAppDrawer,
} = useAdminApps();
const { tokenModalOpen } = useAdminSecurity();
</script>

<template>
  <div
    v-if="appDrawerOpen && selectedApp"
    class="console-overlay-layer"
    @click.self="closeAppDrawer"
  >
    <aside
      class="console-drawer app-drawer"
      role="dialog"
      aria-modal="true"
      aria-label="应用详情"
    >
      <div class="drawer-header">
        <div>
          <h2>{{ selectedApp.appName }}</h2>
          <p class="mono">{{ selectedApp.appId }}</p>
        </div>
        <button
          class="close-button"
          aria-label="关闭应用详情"
          @click="closeAppDrawer"
        >
          ×
        </button>
      </div>
      <div class="drawer-tabs">
        <button
          :class="{ active: appTab === 'overview' }"
          @click="appTab = 'overview'"
        >
          概览与策略</button
        ><button
          :class="{ active: appTab === 'access' }"
          @click="appTab = 'access'"
        >
          准入名单</button
        ><button
          :class="{ active: appTab === 'oidc' }"
          @click="appTab = 'oidc'"
        >
          交互式 OIDC</button
        ><button
          :class="{ active: appTab === 'trust' }"
          @click="appTab = 'trust'"
        >
          信任关系 <span>{{ appTrusts.length }}</span></button
        ><button
          :class="{ active: appTab === 'danger' }"
          @click="appTab = 'danger'"
        >
          危险操作
        </button>
      </div>
      <div class="drawer-body">
        <div v-if="appDetailLoading" class="drawer-loading">
          <span class="console-spinner"></span>加载策略与准入数据…
        </div>
        <template v-else-if="appTab === 'overview'"
          ><div class="detail-identity">
            <span class="resource-glyph large">▦</span>
            <div>
              <b>{{ selectedApp.appName }}</b>
              <p class="mono">aud: {{ selectedApp.audience }}</p>
            </div>
            <span
              class="status-pill"
              :class="appConfig.isActive ? 'green' : 'gray'"
              ><i></i>{{ appConfig.isActive ? "已启用" : "已停用" }}</span
            >
          </div>
          <div class="drawer-section">
            <div class="section-heading">
              <h3>回调与生命周期</h3>
              <span>PUT /callback</span>
            </div>
            <label class="drawer-field"
              >Callback URL<input
                v-model="appConfig.callbackUrl"
                class="console-input"
                placeholder="https://…" /></label
            ><label class="drawer-field"
              >TTL（秒）<input
                v-model.number="appConfig.ttlSeconds"
                class="console-input"
                type="number"
                min="0" /></label
            ><label class="confirm-line"
              ><input
                v-model="appConfig.isActive"
                type="checkbox"
              />允许该应用继续发起认证</label
            >
          </div>
          <div class="drawer-section">
            <div class="section-heading">
              <h3>身份源策略</h3>
              <span>拆分接口，顺序提交</span>
            </div>
            <div class="policy-grid">
              <label
                >LDAP<select
                  v-model="appConfig.ldapLoginMode"
                  class="console-select"
                >
                  <option value="Disabled">关闭</option>
                  <option value="ManualApproval">人工准入</option>
                  <option value="AutoProvision">自动开户</option>
                </select></label
              ><label
                >短信<select
                  v-model="appConfig.smsLoginMode"
                  class="console-select"
                >
                  <option value="Disabled">关闭</option>
                  <option value="ManualApproval">人工准入</option>
                  <option value="AutoProvision">自动开户</option>
                </select></label
              ><label v-if="appConfig.smsLoginMode !== 'Disabled'"
                >短信 Profile<select
                  v-model="appConfig.smsProfileKey"
                  class="console-select"
                >
                  <option value="">未选择</option>
                  <option
                    v-for="profile in smsProfiles"
                    :key="profile.key"
                    :value="profile.key"
                  >
                    {{ profile.key }} · {{ profile.provider }}
                  </option>
                </select></label
              ><label
                >微信<select
                  v-model="appConfig.wechatLoginMode"
                  class="console-select"
                >
                  <option value="Disabled">关闭</option>
                  <option value="BindRequired">需绑定</option>
                  <option value="AutoProvision">自动开户</option>
                </select></label
              ><label
                >Audience<select
                  v-model="appConfig.audienceMode"
                  class="console-select"
                >
                  <option value="Shared">共享</option>
                  <option value="PerApplication">按应用</option>
                </select></label
              >
            </div>
          </div>
          <button
            class="console-button primary full"
            :disabled="appSaving"
            @click="saveAppConfig"
          >
            {{ appSaving ? "保存中…" : "保存应用配置" }}
          </button></template
        >
        <template v-else-if="appTab === 'access'"
          ><div class="drawer-section">
            <div class="section-heading">
              <h3>短信准入</h3>
              <span>{{ appSmsUsers.length }} 条</span>
            </div>
            <div class="drawer-inline-form">
              <input
                v-model="accessForm.phone"
                class="console-input"
                placeholder="输入手机号"
              /><button
                class="console-button secondary compact"
                @click="addSmsUser"
              >
                添加
              </button>
            </div>
            <div
              v-for="item in appSmsUsers"
              :key="item.loginId"
              class="access-row"
            >
              <span
                ><b>{{ item.phone }}</b
                ><small>{{ formatDate(item.createdAt) }}</small></span
              ><button
                class="text-button danger-text"
                @click="revokeSmsUser(item.loginId)"
              >
                撤销
              </button>
            </div>
          </div>
          <div class="drawer-section">
            <div class="section-heading">
              <h3>LDAP 准入</h3>
              <span>{{ appLdapUsers.length }} 条</span>
            </div>
            <div class="drawer-inline-form">
              <select v-model="accessForm.directoryKey" class="console-select">
                <option value="">目录</option>
                <option
                  v-for="directory in ldapDirectories"
                  :key="directory.key"
                  :value="directory.key"
                >
                  {{ directory.key }}
                </option></select
              ><input
                v-model="accessForm.username"
                class="console-input"
                placeholder="域账号"
              /><button
                class="console-button secondary compact"
                @click="addLdapUser"
              >
                添加
              </button>
            </div>
            <div
              v-for="item in appLdapUsers"
              :key="item.credentialId"
              class="access-row"
            >
              <span
                ><b>{{ item.username }}</b
                ><small
                  >{{ item.directoryKey }} ·
                  {{ formatDate(item.createdAt) }}</small
                ></span
              ><button
                class="text-button danger-text"
                @click="revokeLdapUser(item.credentialId)"
              >
                撤销
              </button>
            </div>
          </div>
          <div class="drawer-section">
            <div class="section-heading">
              <h3>微信准入</h3>
              <span>{{ appWechatUsers.length }} 条</span>
            </div>
            <div v-if="!appWechatUsers.length" class="console-empty-inline">
              暂无微信准入记录
            </div>
            <div
              v-for="item in appWechatUsers"
              :key="item.loginId"
              class="access-row"
            >
              <span
                ><b class="mono">{{ item.openId }}</b
                ><small>{{ formatDate(item.createdAt) }}</small></span
              ><button
                v-if="item.isActive"
                class="text-button danger-text"
                @click="revokeWechatUser(item.loginId)"
              >
                撤销</button
              ><button
                v-else
                class="text-button"
                @click="restoreWechatUser(item.loginId)"
              >
                恢复</button
              ><span
                class="status-pill"
                :class="item.isActive ? 'green' : 'gray'"
                ><i></i>{{ item.isActive ? "有效" : "已撤销" }}</span
              >
            </div>
          </div></template
        >
        <template v-else-if="appTab === 'oidc'"
          ><div v-if="oidcLoading" class="drawer-loading">
            <span class="console-spinner"></span>加载交互式 OIDC 配置…
          </div>
          <template v-else
            ><div class="drawer-section">
              <div class="section-heading">
                <h3>客户端类型与状态</h3>
                <span>GET /oidc</span>
              </div>
              <p class="section-description">
                这一页配置的是浏览器授权码登录。它与「概览与策略」里的 Callback URL
                无关：Callback URL 是服务端到服务端的 claims 回调，两者是各自独立的注册，任何一方
                都不会被写入另一方。
              </p>
              <div class="access-row">
                <span
                  ><b>客户端类型</b
                  ><small>{{ oidcConfig.clientType }} · aud 模式
                    {{ oidcConfig.audienceMode }}</small
                  ></span
                ><span
                  class="status-pill"
                  :class="oidcConfig.allowAuthorizationCode ? 'green' : 'gray'"
                  ><i></i
                  >{{
                    oidcConfig.allowAuthorizationCode ? "已启用" : "未启用"
                  }}</span
                >
              </div>
              <p v-if="isPublicClient" class="section-description">
                Public 客户端目前是保留状态，控制台不提供启用路径，也不会提交 Public
                配置。
              </p>
              <p v-if="oidcError" class="inline-error">
                {{ oidcError }}
              </p>
            </div>
            <div class="drawer-section">
              <div class="section-heading">
                <h3>授权码策略</h3>
                <span>PUT /oidc-policy</span>
              </div>
              <label class="confirm-line"
                ><input
                  v-model="oidcPolicyForm.allowAuthorizationCode"
                  type="checkbox"
                  :disabled="isPublicClient"
                />启用授权码流程</label
              ><label class="drawer-field"
                >允许的 scope（空格分隔）<input
                  v-model="oidcPolicyForm.allowedScopes"
                  class="console-input"
                  :disabled="isPublicClient"
                  placeholder="openid profile" /></label
              ><label class="confirm-line"
                ><input
                  v-model="oidcPolicyForm.allowRefreshToken"
                  type="checkbox"
                  :disabled="isPublicClient"
                />允许签发 refresh token</label
              ><label class="drawer-field"
                >身份会话最长有效期（秒，留空表示不限制）<input
                  v-model="oidcPolicyForm.identitySessionMaxAgeSeconds"
                  class="console-input"
                  type="number"
                  min="1"
                  :disabled="isPublicClient" /></label
              >
              <div class="drawer-inline-form">
                <button
                  class="console-button primary compact"
                  :disabled="oidcSaving || isPublicClient"
                  @click="saveOidcPolicy"
                >
                  {{ oidcSaving ? "保存中…" : "保存授权码策略" }}</button
                ><button
                  class="console-button secondary compact"
                  :disabled="oidcSaving"
                  @click="resetPolicyForm"
                >
                  取消编辑
                </button>
              </div>
            </div>
            <div class="drawer-section">
              <div class="section-heading">
                <h3>Redirect URI</h3>
                <span>{{ oidcConfig.redirectUris.length }} 条</span>
              </div>
              <p class="section-description">
                注册值按你输入的精确形式比较：尾斜杠、大小写与端口差异都会让后续授权请求不匹配。
              </p>
              <div class="drawer-inline-form">
                <input
                  v-model="redirectUriDraft"
                  class="console-input mono"
                  placeholder="https://bff.example.test/signin-oidc"
                /><button
                  class="console-button secondary compact"
                  :disabled="oidcSaving"
                  @click="addRedirectUri('Redirect')"
                >
                  注册
                </button>
              </div>
              <div v-if="!oidcConfig.redirectUris.length" class="console-empty-inline">
                暂无 Redirect URI 注册
              </div>
              <div
                v-for="item in oidcConfig.redirectUris"
                :key="item.id"
                class="access-row"
              >
                <span
                  ><b class="mono">{{ item.uri }}</b
                  ><small class="mono">{{ item.id }}</small></span
                ><button
                  class="text-button danger-text"
                  :disabled="oidcSaving"
                  @click="removeRedirectUri(item)"
                >
                  移除
                </button>
              </div>
            </div>
            <div class="drawer-section">
              <div class="section-heading">
                <h3>Post Logout URI</h3>
                <span>{{ oidcConfig.postLogoutRedirectUris.length }} 条</span>
              </div>
              <div class="drawer-inline-form">
                <input
                  v-model="postLogoutUriDraft"
                  class="console-input mono"
                  placeholder="https://bff.example.test/signout-callback-oidc"
                /><button
                  class="console-button secondary compact"
                  :disabled="oidcSaving"
                  @click="addRedirectUri('PostLogout')"
                >
                  注册
                </button>
              </div>
              <div
                v-if="!oidcConfig.postLogoutRedirectUris.length"
                class="console-empty-inline"
              >
                暂无 Post Logout URI 注册
              </div>
              <div
                v-for="item in oidcConfig.postLogoutRedirectUris"
                :key="item.id"
                class="access-row"
              >
                <span
                  ><b class="mono">{{ item.uri }}</b
                  ><small class="mono">{{ item.id }}</small></span
                ><button
                  class="text-button danger-text"
                  :disabled="oidcSaving"
                  @click="removeRedirectUri(item)"
                >
                  移除
                </button>
              </div>
            </div></template
          ></template
        >
        <template v-else-if="appTab === 'trust'"
          ><div class="drawer-section risk-section">
            <div class="section-heading">
              <h3>定向换票信任</h3>
              <span>当前应用接受来源应用 token</span>
            </div>
            <p class="section-description">
              添加信任会扩大当前应用的会话入口。撤销不会结束已经换出的会话。
            </p>
            <div class="drawer-inline-form">
              <input
                v-model="trustSourceAppId"
                class="console-input mono"
                placeholder="来源 App ID"
              /><button
                class="console-button secondary compact"
                @click="addTrust"
              >
                添加信任
              </button>
            </div>
            <div v-if="!appTrusts.length" class="console-empty-inline">
              暂无信任关系
            </div>
            <div
              v-for="trust in appTrusts"
              :key="trust.sourceAppId"
              class="access-row"
            >
              <span
                ><b>{{ trust.sourceAppName }}</b
                ><small class="mono"
                  >{{ trust.sourceAppId }} ·
                  {{ formatDate(trust.createdAt) }}</small
                ></span
              ><button
                class="text-button danger-text"
                @click="removeTrust(trust)"
              >
                撤销
              </button>
            </div>
          </div></template
        >
        <template v-else
          ><div class="danger-callout">
            <span>!</span>
            <div>
              <b>这些操作不可由当前后端恢复</b>
              <p>
                删除应用是物理删除；重置 Secret 会立即使旧凭据失效；撤销 refresh
                token 需要完整原始 token。
              </p>
            </div>
          </div>
          <div class="danger-actions">
            <button
              class="danger-action"
              @click="appActionModal = 'reset-secret'"
            >
              重置 App Secret <small>旧 Secret 立即失效</small></button
            ><button
              class="danger-action"
              @click="
                appActionModal = 'delete-app';
                deleteConfirmId = '';
              "
            >
              删除应用 <small>无恢复接口</small></button
            ><button class="danger-action" @click="tokenModalOpen = true">
              撤销 refresh token <small>需要粘贴原始 token</small>
            </button>
          </div></template
        >
      </div>
    </aside>
  </div>
</template>
