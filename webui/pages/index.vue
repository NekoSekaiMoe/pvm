<template>
  <div>
    <h1>Containers Dashboard</h1>
    
    <div class="glass-card">
      <h3>Launch New Container</h3>
      <div class="input-group">
        <input v-model="newContainer.name" placeholder="Container Name (e.g. web1)" />
        <input v-model="newContainer.rootfs" placeholder="Rootfs Image (default: alpine)" />
        <button class="btn btn-primary" @click="startContainer">Launch Container</button>
        <button class="btn btn-primary" @click="restoreContainer" style="background: var(--text-muted); color: #111;">Restore from Snapshot</button>
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
                <button class="btn btn-primary" @click="snapshotContainer(c.id)" style="margin-right: 0.5rem; background: var(--success);">Snapshot</button>
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
  try {
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
  } catch (e) {
    console.error(e)
    alert(`Network error starting container: ${e.message}`)
  }
}

const restoreContainer = async () => {
  if (!newContainer.value.name) {
    alert("Please enter the original container name to restore from")
    return
  }
  try {
    const res = await fetch(`/api/containers/${newContainer.value.name}/restore`, { method: 'POST' })
    if (res.ok) {
      newContainer.value.name = ''
      alert("Container restored successfully!")
      setTimeout(fetchContainers, 500)
    } else {
      const err = await res.json()
      alert(`Error restoring container: ${err.error || res.statusText}`)
    }
  } catch (e) {
    console.error(e)
    alert(`Network error restoring container: ${e.message}`)
  }
}

const deleteContainer = async (id) => {
  if(!confirm(`Delete container ${id}?`)) return
  try {
    const res = await fetch(`/api/containers/${id}`, { method: 'DELETE' })
    if (res.ok) {
      fetchContainers()
    } else {
      const err = await res.json()
      alert(`Error deleting container: ${err.error || res.statusText}`)
    }
  } catch (e) {
    console.error(e)
    alert(`Network error deleting container: ${e.message}`)
  }
}

const snapshotContainer = async (id) => {
  if(!confirm(`Snapshot container ${id}?`)) return
  try {
    const res = await fetch(`/api/containers/${id}/snapshot`, { method: 'POST' })
    if (res.ok) {
      alert(`Snapshot for ${id} created successfully!`)
    } else {
      const err = await res.json()
      alert(`Error creating snapshot: ${err.error || res.statusText}`)
    }
  } catch (e) {
    console.error(e)
    alert(`Network error: ${e.message}`)
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
