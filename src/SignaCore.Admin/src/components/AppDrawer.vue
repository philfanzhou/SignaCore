<script setup lang="ts">
import { computed } from 'vue'
import { useApps } from '../composables/useApps'
import { I } from '../utils/icons'

const {
  apps,
  appDrawerVisible,
  appDrawerOpen,
  appDrawerApp,
  callbackForm,
  savingCallback,
  resettingSecret,
  loadingLdapUsers,
  addingLdapUser,
  ldapUsers,
  ldapDirectories,
  ldapUserForm,
  loadingSmsUsers,
  addingSmsUser,
  smsUsers,
  smsProfiles,
  smsUserForm,
  loadingWechatUsers,
  wechatUsers,
  loadingExchangeTrusts,
  addingExchangeTrust,
  exchangeTrusts,
  exchangeTrustForm,
  closeAppDrawer,
  saveCallbackFromDrawer,
  handleResetSecret,
  openDeleteAppModal,
  addLdapUser,
  revokeLdapUser,
  addSmsUser,
  revokeSmsUser,
  revokeWechatUser,
  restoreWechatUser,
  addExchangeTrust,
  removeExchangeTrust,
} = useApps()

/** 准入来源的展示名。ExchangeGranted 必须和自动开户区分开——那条记录背后没有任何验证过程。 */
const approvalSourceLabels: Record<string, string> = {
  Admin: '管理员',
  AutoProvision: '自动开户',
  SelfBind: '用户绑定',
  ExchangeGranted: '跨应用换票',
}

function approvalSourceLabel(source: string) {
  return approvalSourceLabels[source] ?? source
}

/** 可选的来源应用：除自己以外的全部应用，已经加过的边不再重复列出。 */
const availableTrustSources = computed(() => {
  const current = appDrawerApp.value?.appId
  const existing = new Set(exchangeTrusts.value.map((trust) => trust.sourceAppId))
  return apps.value.filter((app) => app.appId !== current && !existing.has(app.appId))
})
</script>

<template>
  <!-- ============ 应用 Drawer ============ -->
  <template v-if="appDrawerVisible && appDrawerApp">
    <div class="overlay" :class="{ open: appDrawerOpen }" @click="closeAppDrawer"></div>
    <div class="drawer" :class="{ open: appDrawerOpen }">
      <div class="drawer-head">
        <div class="cell-app-icon" style="width: 40px; height: 40px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.app"></svg>
        </div>
        <div style="flex: 1">
          <div class="drawer-title">{{ appDrawerApp.appName }}</div>
          <div class="drawer-sub mono">{{ appDrawerApp.appId }}</div>
        </div>
        <span class="badge" :class="appDrawerApp.isActive ? 'green' : 'gray'">
          <span class="dot"></span>{{ appDrawerApp.isActive ? '已启用' : '已停用' }}
        </span>
        <button class="icon-btn" @click="closeAppDrawer">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.x"></svg>
        </button>
      </div>
      <div class="drawer-body">
        <div class="card" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">回调配置</div>
          <div class="field">
            <label>回调地址（Callback URL）</label>
            <input v-model="callbackForm.callbackUrl" class="input" style="width: 100%" placeholder="https://your-app.example.com/auth/callback">
            <div class="hint">留空表示纯服务端应用，不使用浏览器回调。</div>
          </div>
          <div class="field">
            <label>回调有效期</label>
            <div class="input-with-unit">
              <input v-if="!callbackForm.neverExpire" v-model.number="callbackForm.ttlSeconds" class="input" type="number" min="1">
              <input v-else class="input" :value="'永不过期'" disabled>
              <select v-model="callbackForm.ttlUnit" class="select" :disabled="callbackForm.neverExpire">
                <option value="h">小时</option>
                <option value="d">天</option>
              </select>
            </div>
            <div class="hint">到期后回调地址自动失效，需重新配置。保存即从此刻重新计时。</div>
          </div>
          <div class="field" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0">
            <label style="margin: 0">启用该应用</label>
            <label class="switch">
              <input v-model="callbackForm.isActive" type="checkbox">
              <span class="track"></span>
            </label>
          </div>
        </div>
        <div class="card section-gap" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">LDAP 登录</div>
          <div class="field">
            <label>当前应用准入模式</label>
            <select v-model="callbackForm.ldapLoginMode" class="select" style="width: 100%">
              <option value="Disabled">禁用 LDAP 登录</option>
              <option value="ManualApproval">仅管理员授权用户</option>
              <option value="AutoProvision">验证成功自动开户</option>
            </select>
            <div class="hint">从自动模式切换为手动模式后，自动开户记录不会被视为管理员授权。</div>
          </div>
          <div class="field">
            <label>为当前应用授权 LDAP 用户</label>
            <div style="display: grid; grid-template-columns: 130px 1fr auto; gap: 8px">
              <select v-model="ldapUserForm.directoryKey" class="select">
                <option v-for="directory in ldapDirectories" :key="directory.key" :value="directory.key">
                  {{ directory.key }}{{ directory.isDefault ? '（默认）' : '' }}
                </option>
              </select>
              <input v-model="ldapUserForm.username" class="input" placeholder="alice 或 alice@corp.example.com" @keyup.enter="addLdapUser">
              <button class="btn btn-sm" :disabled="addingLdapUser || !ldapDirectories.length" @click="addLdapUser">授权</button>
            </div>
          </div>
          <div v-if="loadingLdapUsers" class="hint">正在加载授权用户...</div>
          <div v-else-if="ldapUsers.length === 0" class="hint">当前应用还没有 LDAP 用户授权记录。</div>
          <div v-else class="table-wrap">
            <table class="data-table">
              <thead><tr><th>账号</th><th>目录</th><th>来源</th><th>状态</th><th></th></tr></thead>
              <tbody>
                <tr v-for="user in ldapUsers" :key="user.credentialId">
                  <td><div class="td-main">{{ user.username }}</div><div class="mono" style="font-size: 11px; color: var(--text-3)">{{ user.samAccountName }}</div></td>
                  <td class="mono">{{ user.directoryKey }}</td>
                  <td>{{ approvalSourceLabel(user.approvalSource) }}</td>
                  <td><span class="badge" :class="user.isActive ? 'green' : 'gray'"><span class="dot"></span>{{ user.isActive ? '有效' : '已撤销' }}</span></td>
                  <td><button v-if="user.isActive" class="btn btn-danger btn-sm" @click="revokeLdapUser(user)">撤销</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card section-gap" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">手机验证码登录</div>
          <div class="field">
            <label>当前应用准入模式</label>
            <select v-model="callbackForm.smsLoginMode" class="select" style="width: 100%">
              <option value="Disabled">禁用手机验证码登录</option>
              <option value="ManualApproval">仅管理员授权用户</option>
              <option value="AutoProvision">验证成功自动开户</option>
            </select>
            <div class="hint">切回手工模式后，自动开户记录不会被视为管理员授权。</div>
          </div>
          <div class="field">
            <label>短信供应商配置</label>
            <select v-model="callbackForm.smsProfileKey" class="select" style="width: 100%">
              <option value="">不配置供应商（仅测试白名单可登录）</option>
              <option v-for="profile in smsProfiles" :key="profile.key" :value="profile.key">
                {{ profile.key }}（{{ profile.provider }}）
              </option>
            </select>
            <div class="hint">
              密钥与模板保存在部署配置中，后台只保存配置名称。留空表示不下发验证码，只有
              <span class="mono">Sms:BypassPhones</span> 白名单内的号码能用固定测试码登录。
            </div>
          </div>
          <div class="field">
            <label>为当前应用授权手机用户</label>
            <div style="display: grid; grid-template-columns: 1fr auto; gap: 8px">
              <input v-model="smsUserForm.phone" class="input" placeholder="13800138000 或 +8613800138000" @keyup.enter="addSmsUser">
              <button class="btn btn-sm" :disabled="addingSmsUser" @click="addSmsUser">授权</button>
            </div>
          </div>
          <div v-if="loadingSmsUsers" class="hint">正在加载授权用户...</div>
          <div v-else-if="smsUsers.length === 0" class="hint">当前应用还没有手机用户授权记录。</div>
          <div v-else class="table-wrap">
            <table class="data-table">
              <thead><tr><th>手机号</th><th>来源</th><th>状态</th><th></th></tr></thead>
              <tbody>
                <tr v-for="user in smsUsers" :key="user.loginId">
                  <td class="mono">{{ user.phone }}</td>
                  <td>{{ approvalSourceLabel(user.approvalSource) }}</td>
                  <td><span class="badge" :class="user.isActive ? 'green' : 'gray'"><span class="dot"></span>{{ user.isActive ? '有效' : '已撤销' }}</span></td>
                  <td><button v-if="user.isActive" class="btn btn-danger btn-sm" @click="revokeSmsUser(user)">撤销</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card section-gap" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">微信登录</div>
          <div class="field">
            <label>当前应用准入模式</label>
            <select v-model="callbackForm.wechatLoginMode" class="select" style="width: 100%">
              <option value="Disabled">禁用微信登录</option>
              <option value="BindRequired">仅已绑定微信的账号</option>
              <option value="AutoProvision">首次授权自动开户</option>
            </select>
            <div class="hint">
              OpenId 只有用户授权后才可知，所以没有"管理员预授权"模式：绑定由用户自己在
              <span class="mono">POST /api/profile/wechat</span> 完成，管理员做撤销与恢复。
              撤销后用户重新绑定也不会自动解封，只能从这里恢复。
            </div>
          </div>
          <div v-if="loadingWechatUsers" class="hint">正在加载绑定用户...</div>
          <div v-else-if="wechatUsers.length === 0" class="hint">当前应用还没有微信绑定记录。</div>
          <div v-else class="table-wrap">
            <table class="data-table">
              <thead><tr><th>OpenId</th><th>来源</th><th>状态</th><th></th></tr></thead>
              <tbody>
                <tr v-for="user in wechatUsers" :key="user.loginId">
                  <td class="mono">{{ user.openId }}</td>
                  <td>{{ approvalSourceLabel(user.approvalSource) }}</td>
                  <td><span class="badge" :class="user.isActive ? 'green' : 'gray'"><span class="dot"></span>{{ user.isActive ? '有效' : '已撤销' }}</span></td>
                  <td>
                    <button v-if="user.isActive" class="btn btn-danger btn-sm" @click="revokeWechatUser(user)">撤销</button>
                    <button v-else class="btn btn-sm" @click="restoreWechatUser(user)">恢复</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card section-gap" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">跨应用换票信任</div>
          <div class="field">
            <label>接受哪些应用签发的 refresh token</label>
            <div style="display: grid; grid-template-columns: 1fr auto; gap: 8px">
              <select v-model="exchangeTrustForm.sourceAppId" class="select">
                <option value="">选择来源应用</option>
                <option v-for="app in availableTrustSources" :key="app.appId" :value="app.appId">
                  {{ app.appName }}（{{ app.appId }}）{{ app.isActive ? '' : '（已停用）' }}
                </option>
              </select>
              <button class="btn btn-sm" :disabled="addingExchangeTrust || !exchangeTrustForm.sourceAppId" @click="addExchangeTrust">添加</button>
            </div>
            <div class="hint">
              信任是有向的：这里配的是「当前应用接受谁的票」，反过来不成立。持有来源应用 refresh token
              的人可以直接换到当前应用的会话，不需要重新登录——当前应用权限更高时，差异必须由回调和
              授权规则守住。换票只签发新票，不会吊销来源应用手上那张；换出来的票不能再换第二次，
              所以信任不会沿着两条边传递。
            </div>
          </div>
          <div v-if="loadingExchangeTrusts" class="hint">正在加载换票信任...</div>
          <div v-else-if="exchangeTrusts.length === 0" class="hint">当前应用不接受任何其他应用签发的 refresh token。</div>
          <div v-else class="table-wrap">
            <table class="data-table">
              <thead><tr><th>来源应用</th><th>状态</th><th></th></tr></thead>
              <tbody>
                <tr v-for="trust in exchangeTrusts" :key="trust.sourceAppId">
                  <td><div class="td-main">{{ trust.sourceAppName }}</div><div class="mono" style="font-size: 11px; color: var(--text-3)">{{ trust.sourceAppId }}</div></td>
                  <td><span class="badge" :class="trust.sourceIsActive ? 'green' : 'gray'"><span class="dot"></span>{{ trust.sourceIsActive ? '有效' : '来源已停用' }}</span></td>
                  <td><button class="btn btn-danger btn-sm" @click="removeExchangeTrust(trust)">撤销</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="card section-gap" style="padding: 20px">
          <div class="card-title" style="margin-bottom: 16px">Access token 受众（aud）</div>
          <div class="field">
            <label>受众模式</label>
            <select v-model="callbackForm.audienceMode" class="select" style="width: 100%">
              <option value="Shared">共享受众（所有应用同一个 aud）</option>
              <option value="PerApplication">按应用隔离（aud = 本应用 AppId）</option>
            </select>
            <div class="hint">
              当前生效：<span class="mono">{{ appDrawerApp.audience }}</span>。
              共享模式下，签给本应用的 access token 在其他应用同样校验通过——受众不构成边界。
              切到按应用隔离前，必须先让下游同时接受两个 aud，否则在用的 token 会被下游拒掉。
            </div>
          </div>
        </div>
        <div class="danger-zone section-gap">
          <div class="dz-title">重置密钥</div>
          <div class="dz-desc">生成新的 App Secret，旧 Secret 立即失效。新 Secret 仅显示一次。</div>
          <button class="btn btn-danger btn-sm" :disabled="resettingSecret" @click="handleResetSecret(appDrawerApp)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" v-html="I.refresh"></svg>
            重置密钥
          </button>
          <div class="dz-title" style="margin-top: 14px">删除应用</div>
          <div class="dz-desc">删除后使用该应用接入的所有登录将立即失败。</div>
          <button class="btn btn-danger btn-sm" @click="openDeleteAppModal(appDrawerApp)">删除应用</button>
        </div>
      </div>
      <div class="drawer-foot">
        <button class="btn btn-ghost" @click="closeAppDrawer">取消</button>
        <button class="btn" :disabled="savingCallback" @click="saveCallbackFromDrawer">保存配置</button>
      </div>
    </div>
  </template>
</template>
