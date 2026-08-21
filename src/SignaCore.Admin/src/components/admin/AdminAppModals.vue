<script setup lang="ts">
import { useAdminApps } from "../../composables/admin/useAdminApps";

const {
  appModalOpen,
  appSavingNew,
  createAppForm,
  appActionModal,
  secretValue,
  secretAcknowledged,
  deleteConfirmId,
  destructiveBusy,
  selectedApp,
  createApp,
  resetAppSecret,
  deleteApp,
  closeActionModal,
  copySecret,
} = useAdminApps();
</script>

<template>
  <div
    v-if="appModalOpen"
    class="console-modal-layer"
    @click.self="appModalOpen = false"
  >
    <section
      class="console-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="app-modal-title"
    >
      <div class="modal-header">
        <div>
          <span class="console-eyebrow">NEW RESOURCE</span>
          <h2 id="app-modal-title">注册应用</h2>
        </div>
        <button
          class="close-button"
          aria-label="关闭"
          @click="appModalOpen = false"
        >
          ×
        </button>
      </div>
      <div class="modal-body">
        <div class="console-info-band compact-band">
          <span>ⓘ</span>
          <p>注册成功后 App Secret 只展示一次，请在受控环境保存。</p>
        </div>
        <label
          >应用名称<input
            v-model="createAppForm.appName"
            class="console-input" /></label
        ><label
          >Callback URL<input
            v-model="createAppForm.callbackUrl"
            class="console-input mono"
            placeholder="https://client.example/callback" /></label
        ><label
          >回调有效期（秒）<input
            v-model.number="createAppForm.ttlSeconds"
            class="console-input"
            type="number"
            min="0"
          /><small>填 0 表示不设置过期时间。</small></label
        >
      </div>
      <div class="modal-footer">
        <button class="console-button secondary" @click="appModalOpen = false">
          取消</button
        ><button
          class="console-button primary"
          :disabled="appSavingNew"
          @click="createApp"
        >
          {{ appSavingNew ? "注册中…" : "注册应用" }}
        </button>
      </div>
    </section>
  </div>

  <div
    v-if="appActionModal === 'secret'"
    class="console-modal-layer strict-layer"
  >
    <section
      class="console-modal secret-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="secret-title"
    >
      <div class="modal-header">
        <div>
          <span class="console-eyebrow">ONE-TIME CREDENTIAL</span>
          <h2 id="secret-title">保存新的 App Secret</h2>
        </div>
      </div>
      <div class="modal-body">
        <div class="secret-warning">
          <span>!</span>
          <p>
            此 Secret
            只会从后端返回一次。关闭窗口后无法再次查看，请使用受控凭据保管方式保存。
          </p>
        </div>
        <div class="secret-value">
          <code>{{ secretValue }}</code
          ><button class="console-button secondary compact" @click="copySecret">
            复制
          </button>
        </div>
        <label class="confirm-line"
          ><input v-model="secretAcknowledged" type="checkbox" />我已将 Secret
          保存到安全位置，可以关闭此窗口</label
        >
      </div>
      <div class="modal-footer">
        <button
          class="console-button primary"
          :disabled="!secretAcknowledged"
          @click="closeActionModal"
        >
          完成并关闭
        </button>
      </div>
    </section>
  </div>

  <div
    v-if="appActionModal === 'reset-secret'"
    class="console-modal-layer"
    @click.self="appActionModal = null"
  >
    <section
      class="console-modal danger-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reset-title"
    >
      <div class="modal-header">
        <div>
          <span class="console-eyebrow">ROTATE CREDENTIAL</span>
          <h2 id="reset-title">重置 App Secret？</h2>
        </div>
        <button
          class="close-button"
          aria-label="关闭"
          @click="appActionModal = null"
        >
          ×
        </button>
      </div>
      <div class="modal-body">
        <div class="danger-callout">
          <span>!</span>
          <div>
            <b>旧 Secret 会立即失效</b>
            <p>
              所有使用旧凭据的客户端都会认证失败。确认客户端已经准备好切换新
              Secret。
            </p>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="console-button secondary" @click="appActionModal = null">
          取消</button
        ><button
          class="console-button danger"
          :disabled="destructiveBusy"
          @click="
            appActionModal = null;
            resetAppSecret();
          "
        >
          确认重置
        </button>
      </div>
    </section>
  </div>

  <div
    v-if="appActionModal === 'delete-app' && selectedApp"
    class="console-modal-layer"
    @click.self="appActionModal = null"
  >
    <section
      class="console-modal danger-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-title"
    >
      <div class="modal-header">
        <div>
          <span class="console-eyebrow">IRREVERSIBLE ACTION</span>
          <h2 id="delete-title">删除 {{ selectedApp.appName }}？</h2>
        </div>
        <button
          class="close-button"
          aria-label="关闭"
          @click="appActionModal = null"
        >
          ×
        </button>
      </div>
      <div class="modal-body">
        <div class="danger-callout">
          <span>!</span>
          <div>
            <b>后端执行物理删除，当前没有恢复接口。</b>
            <p>删除前请确认下游客户端已经迁移或停用。</p>
          </div>
        </div>
        <label
          >输入 App ID 确认<input
            v-model="deleteConfirmId"
            class="console-input mono"
            :placeholder="selectedApp.appId"
        /></label>
      </div>
      <div class="modal-footer">
        <button class="console-button secondary" @click="appActionModal = null">
          取消</button
        ><button
          class="console-button danger"
          :disabled="deleteConfirmId !== selectedApp.appId || destructiveBusy"
          @click="deleteApp"
        >
          确认删除
        </button>
      </div>
    </section>
  </div>
</template>
