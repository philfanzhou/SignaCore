<script setup lang="ts">
import { useUsers } from '../../composables/useUsers'

const {
  editRemarkOpen,
  editRemarkTarget,
  editRemarkValue,
  saveEditRemark,
} = useUsers()
</script>

<template>
  <!-- ============ 编辑备注 Modal ============ -->
  <template v-if="editRemarkOpen && editRemarkTarget">
    <div class="modal-wrap">
      <div class="overlay" style="position: absolute" @click="editRemarkOpen = false"></div>
      <div class="modal">
        <div class="modal-title">编辑备注</div>
        <div class="modal-sub">{{ editRemarkTarget.username || editRemarkTarget.displayName || editRemarkTarget.userId }} 的备注信息</div>
        <div class="field">
          <input v-model="editRemarkValue" class="input" style="width: 100%" placeholder="备注内容（不超过 200 字符）" maxlength="200">
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" @click="editRemarkOpen = false">取消</button>
          <button class="btn" @click="saveEditRemark">保存</button>
        </div>
      </div>
    </div>
  </template>
</template>
