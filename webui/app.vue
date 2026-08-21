<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="logo">PVM Dashboard</div>
      <nav>
        <div class="section-title">Runtime</div>
        <NuxtLink to="/" class="nav-link">Containers</NuxtLink>
        <NuxtLink to="/images" class="nav-link">Images</NuxtLink>
        <NuxtLink to="/tasks" class="nav-link">Tasks</NuxtLink>
        <NuxtLink to="/volumes" class="nav-link">Volumes</NuxtLink>
        <NuxtLink to="/templates" class="nav-link">Templates</NuxtLink>
        <NuxtLink to="/pool" class="nav-link">Pool &amp; Quota</NuxtLink>
        <NuxtLink to="/terminal" class="nav-link">Tool Terminal</NuxtLink>
        
        <div class="section-title" style="margin-top: 1rem;">Governance &amp; Security</div>
        <NuxtLink to="/approvals" class="nav-link">Approvals</NuxtLink>
        <NuxtLink to="/policy" class="nav-link">Policy</NuxtLink>
        <NuxtLink to="/gate" class="nav-link">Artifact Gate</NuxtLink>
        <NuxtLink to="/audit" class="nav-link">Audit</NuxtLink>
        <NuxtLink to="/network" class="nav-link">Network &amp; Egress</NuxtLink>
        <NuxtLink to="/incidents" class="nav-link">Incidents</NuxtLink>
        <NuxtLink to="/identity" class="nav-link">Identity &amp; Tokens</NuxtLink>
      </nav>
    </aside>
    <main class="main-content">
      <NuxtPage />
    </main>
  </div>
</template>
