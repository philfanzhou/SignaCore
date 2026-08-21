<script setup lang="ts">
import { useAdminSecurity } from "../../composables/admin/useAdminSecurity";

const {
  tokenModalOpen,
  tokenValue,
  tokenBusy,
  revokeToken,
  closeTokenModal,
} = useAdminSecurity();
</script>

<template>
  <div
    v-if="tokenModalOpen"
    class="console-modal-layer"
    @click.self="closeTokenModal"
  >
    <section
      class="console-modal danger-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="token-title"
    >
      <div class="modal-header">
        <div>
          <span class="console-eyebrow">SESSION REVOCATION</span>
          <h2 id="token-title">撤销 refresh token</h2>
        </div>
        <button class="close-button" aria-label="关闭" @click="closeTokenModal">
          ×
        </button>
      </div>
      <div class="modal-body">
        <div class="danger-callout">
          <span>!</span>
          <div>
            <b>后端只接受完整原始 token</b>
            <p>
              当前没有 token 列表或批量撤销接口。撤销成功后该 token 不能恢复。
            </p>
          </div>
        </div>
        <label
          >原始 refresh token<textarea
            v-model="tokenValue"
            class="console-input mono"
            rows="5"
            spellcheck="false"
          ></textarea
        ></label>
      </div>
      <div class="modal-footer">
        <button class="console-button secondary" @click="closeTokenModal">
          取消</button
        ><button
          class="console-button danger"
          :disabled="!tokenValue.trim() || tokenBusy"
          @click="revokeToken"
        >
          确认撤销
        </button>
      </div>
    </section>
  </div>
</template>
