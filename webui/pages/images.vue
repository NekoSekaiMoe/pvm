<template>
  <div>
    <h1>{{ t('pages.images.title') }}</h1>
    <p class="muted">{{ t('pages.images.subtitle') }}</p>

    <!-- Quick Presets -->
    <div class="glass-card">
      <h3>{{ t('pages.images.presetsTitle') }}</h3>
      <p class="muted" style="margin-bottom:1rem;">{{ t('pages.images.presetsHint') }}</p>
      
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
        <button class="btn btn-primary" style="font-size:0.85rem;" @click="selectPreset('alpine:3.19')">Alpine 3.19</button>
        <button class="btn btn-primary" style="font-size:0.85rem;" @click="selectPreset('ubuntu:22.04')">Ubuntu 22.04</button>
        <button class="btn btn-primary" style="font-size:0.85rem;" @click="selectPreset('debian:bookworm-slim')">Debian Bookworm</button>
        <button class="btn btn-primary" style="font-size:0.85rem;" @click="selectPreset('python:3.11-alpine')">Python 3.11</button>
        <button class="btn btn-primary" style="font-size:0.85rem;" @click="selectPreset('node:20-alpine')">Node.js 20</button>
      </div>
    </div>
    
    <!-- Custom Pull Card -->
    <div class="glass-card">
      <h3>{{ t('pages.images.customTitle') }}</h3>
      <p class="muted" style="margin-bottom:1rem;">{{ t('pages.images.customHint') }}</p>
      
      <div class="input-group">
        <input v-model="imageName" :placeholder="t('pages.images.namePh')" @keyup.enter="pullImage" />
        <button class="btn btn-primary" @click="pullImage" :disabled="pulling">
          {{ pulling ? t('pages.images.btnPulling') : t('pages.images.btnPull') }}
        </button>
      </div>
      
      <div v-if="message" class="callout" :class="isError ? 'err' : 'ok'" style="margin-top:1rem;">
        {{ message }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

const imageName = ref('alpine:3.19')
const pulling = ref(false)
const message = ref('')
const isError = ref(false)

const selectPreset = (img) => {
  imageName.value = img
}

const pullImage = async () => {
  if (!imageName.value) return
  pulling.value = true
  message.value = t('pages.images.msgPulling')
  isError.value = false
  
  try {
    const res = await fetch('/api/images/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image: imageName.value })
    })
    
    if (res.ok) {
      message.value = t('pages.images.msgDone', { img: imageName.value })
    } else {
      const err = await res.json()
      message.value = t('pages.images.msgErr', { msg: err.error || res.statusText })
      isError.value = true
    }
  } catch (e) {
    message.value = t('pages.images.msgNetErr', { msg: e.message })
    isError.value = true
  } finally {
    pulling.value = false
  }
}
</script>
