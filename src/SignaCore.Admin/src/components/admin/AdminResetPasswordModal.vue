<script setup lang="ts">
import { useAdminUsers } from "../../composables/admin/useAdminUsers";
const { resetPasswordTarget, resetPasswordForm, resetPasswordSaving, resetPasswordError,
  closeResetPassword, resetUserPassword } = useAdminUsers();
</script>

<template>
  <div v-if="resetPasswordTarget" class="console-modal-layer" @click.self="closeResetPassword"
    @keydown.esc="closeResetPassword">
    <form class="console-modal" role="dialog" aria-modal="true"
      aria-labelledby="reset-password-title" @submit.prevent="resetUserPassword">
      <div class="modal-header">
        <h2 id="reset-password-title">Reset password</h2>
        <button type="button" class="close-button" aria-label="Close password reset"
          @click="closeResetPassword">×</button>
      </div>
      <div class="modal-body">
        <p>{{ resetPasswordTarget.username }}</p>
        <label>New password<input v-model="resetPasswordForm.newPassword" type="password"
          autocomplete="new-password" class="console-input" :disabled="resetPasswordSaving" /></label>
        <label>Confirm password<input v-model="resetPasswordForm.confirmation" type="password"
          autocomplete="new-password" class="console-input" :disabled="resetPasswordSaving" /></label>
        <small>Administrator resets bypass password length and complexity requirements. The password cannot be blank.</small>
        <p>This keeps existing sessions and tokens active and does not unlock the account.</p>
        <p v-if="resetPasswordError" role="alert" class="danger-text">{{ resetPasswordError }}</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="console-button secondary" @click="closeResetPassword">Cancel</button>
        <button type="submit" class="console-button primary" :disabled="resetPasswordSaving">
          {{ resetPasswordSaving ? "Resetting…" : "Reset password" }}
        </button>
      </div>
    </form>
  </div>
</template>
