<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="logo">PVM Dashboard</div>
      <nav>
        <NuxtLink to="/" class="nav-link">Containers</NuxtLink>
        <NuxtLink to="/images" class="nav-link">Images</NuxtLink>
      </nav>
    </aside>
    <main class="main-content">
      <NuxtPage />
    </main>
  </div>
</template>
