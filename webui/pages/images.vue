<template>
  <div>
    <h1>Base Image Management</h1>
    <p class="muted">Pull and synthesize ext4 rootfs images from Docker registries.</p>

    <!-- Quick Presets -->
    <div class="glass-card">
      <h3>Quick Pull Presets</h3>
      <p class="muted" style="margin-bottom:1rem;">Click any popular base image to pre-populate and pull:</p>
      
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
      <h3>Pull Custom Docker Image</h3>
      <p class="muted" style="margin-bottom:1rem;">Exports layers via <code>crane</code> into a standalone ext4 block device image.</p>
      
      <div class="input-group">
        <input v-model="imageName" placeholder="Image Name (e.g. alpine:latest, golang:1.22-alpine)" @keyup.enter="pullImage" />
        <button class="btn btn-primary" @click="pullImage" :disabled="pulling">
          {{ pulling ? 'Pulling & Synthesizing Ext4...' : 'Pull Image' }}
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
  message.value = 'Contacting Docker registry and exporting rootfs layers...'
  isError.value = false
  
  try {
    const res = await fetch('/api/images/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image: imageName.value })
    })
    
    if (res.ok) {
      message.value = `Successfully pulled and generated rootfs for ${imageName.value}!`
    } else {
      const err = await res.json()
      message.value = `Error: ${err.error || res.statusText}`
      isError.value = true
    }
  } catch (e) {
    message.value = `Network error: ${e.message}`
    isError.value = true
  } finally {
    pulling.value = false
  }
}
</script>
