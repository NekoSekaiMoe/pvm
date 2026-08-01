<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="logo">PVM Dashboard</div>
      <nav>
        <div class="section-title">Runtime</div>
        <NuxtLink to="/" class="nav-link">Containers</NuxtLink>
        <NuxtLink to="/images" class="nav-link">Images</NuxtLink>
        <NuxtLink to="/tasks" class="nav-link">Tasks</NuxtLink>
        <NuxtLink to="/pool" class="nav-link">Pool &amp; Quota</NuxtLink>
        <div class="section-title" style="margin-top: 1rem;">Governance</div>
        <NuxtLink to="/approvals" class="nav-link">Approvals</NuxtLink>
        <NuxtLink to="/policy" class="nav-link">Policy</NuxtLink>
        <NuxtLink to="/audit" class="nav-link">Audit</NuxtLink>
      </nav>
    </aside>
    <main class="main-content">
      <NuxtPage />
    </main>
  </div>
</template>
