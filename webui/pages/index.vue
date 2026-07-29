<template>
  <div>
    <h1>Containers Dashboard</h1>
    
    <div class="glass-card">
      <h3>Launch New Container</h3>
      <div class="input-group">
        <input v-model="newContainer.name" placeholder="Container Name (e.g. web1)" />
        <input v-model="newContainer.rootfs" placeholder="Rootfs Image (default: alpine)" />
        <button class="btn btn-primary" @click="startContainer">Launch Container</button>
      </div>
    </div>

    <div class="glass-card">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID / Name</th>
              <th>Status</th>
              <th>PID</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in containers" :key="c.id">
              <td>{{ c.id }}</td>
              <td>
                <span class="badge" :class="c.status.toLowerCase()">{{ c.status }}</span>
              </td>
              <td>{{ c.pid }}</td>
              <td>
                <NuxtLink :to="`/logs/${c.id}`" class="btn btn-primary" style="margin-right: 0.5rem; text-decoration: none; font-size: 0.875rem;">Logs</NuxtLink>
                <button class="btn btn-danger" @click="deleteContainer(c.id)">Delete</button>
              </td>
            </tr>
            <tr v-if="containers.length === 0">
              <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">No containers found.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const containers = ref([])
const newContainer = ref({ name: '', rootfs: 'alpine', mem: '512M' })
let timer

const fetchContainers = async () => {
  try {
    const res = await fetch('/api/containers')
    if (res.ok) containers.value = await res.json()
  } catch (e) {
    console.error(e)
  }
}

const startContainer = async () => {
  if (!newContainer.value.name) return
  const res = await fetch('/api/containers/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(newContainer.value)
  })
  if (res.ok) {
    newContainer.value.name = ''
    setTimeout(fetchContainers, 500)
  } else {
    const err = await res.json()
    alert(`Error starting container: ${err.error || res.statusText}`)
  }
}

const deleteContainer = async (id) => {
  if(!confirm(`Delete container ${id}?`)) return
  const res = await fetch(`/api/containers/${id}`, { method: 'DELETE' })
  if (res.ok) {
    fetchContainers()
  } else {
    const err = await res.json()
    alert(`Error deleting container: ${err.error || res.statusText}`)
  }
}

onMounted(() => {
  fetchContainers()
  timer = setInterval(fetchContainers, 2000)
})

onUnmounted(() => {
  clearInterval(timer)
})
</script>
