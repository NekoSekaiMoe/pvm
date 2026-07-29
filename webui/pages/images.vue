<template>
  <div>
    <h1>Image Management</h1>
    
    <div class="glass-card">
      <h3>Pull Docker Image</h3>
      <p style="color: var(--text-muted); margin-bottom: 1rem;">Pull a base image from Docker Hub to use as a rootfs.</p>
      
      <div class="input-group">
        <input v-model="imageName" placeholder="Image Name (e.g. ubuntu:latest)" />
        <button class="btn btn-primary" @click="pullImage" :disabled="pulling">
          {{ pulling ? 'Pulling...' : 'Pull Image' }}
        </button>
      </div>
      
      <div v-if="message" :style="{ marginTop: '1rem', fontWeight: '500', color: isError ? 'var(--danger)' : 'var(--success)' }">
        {{ message }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const imageName = ref('')
const pulling = ref(false)
const message = ref('')
const isError = ref(false)

const pullImage = async () => {
  if (!imageName.value) return
  pulling.value = true
  message.value = ''
  isError.value = false
  
  try {
    const res = await fetch('/api/images/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image: imageName.value })
    })
    
    if (res.ok) {
      message.value = `Successfully pulled image ${imageName.value}!`
      imageName.value = ''
    } else {
      const err = await res.json()
      message.value = `Error: ${err.error}`
      isError.value = true
    }
  } catch (e) {
    message.value = `Network error.`
    isError.value = true
  } finally {
    pulling.value = false
  }
}
</script>
