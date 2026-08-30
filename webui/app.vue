<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="logo">{{ t('app.title') }}</div>
      <button
        class="nav-link lang-toggle"
        :title="locale === 'en' ? '切换到中文' : 'Switch to English'"
        @click="toggleLocale"
      >
        🌐 {{ t('app.switchLang') }}
      </button>
      <nav>
        <div class="section-title">{{ t('nav.runtime') }}</div>
        <NuxtLink to="/" class="nav-link">{{ t('nav.containers') }}</NuxtLink>
        <NuxtLink to="/images" class="nav-link">{{ t('nav.images') }}</NuxtLink>
        <NuxtLink to="/tasks" class="nav-link">{{ t('nav.tasks') }}</NuxtLink>
        <NuxtLink to="/console" class="nav-link">{{ t('nav.console') }}</NuxtLink>
        <NuxtLink to="/ephemeral" class="nav-link">{{ t('nav.ephemeral') }}</NuxtLink>
        <NuxtLink to="/volumes" class="nav-link">{{ t('nav.volumes') }}</NuxtLink>
        <NuxtLink to="/templates" class="nav-link">{{ t('nav.templates') }}</NuxtLink>
        <NuxtLink to="/pool" class="nav-link">{{ t('nav.pool') }}</NuxtLink>

        <div class="section-title" style="margin-top: 1rem;">{{ t('nav.governance') }}</div>
        <NuxtLink to="/approvals" class="nav-link">{{ t('nav.approvals') }}</NuxtLink>
        <NuxtLink to="/policy" class="nav-link">{{ t('nav.policy') }}</NuxtLink>
        <NuxtLink to="/gate" class="nav-link">{{ t('nav.gate') }}</NuxtLink>
        <NuxtLink to="/audit" class="nav-link">{{ t('nav.audit') }}</NuxtLink>
        <NuxtLink to="/network" class="nav-link">{{ t('nav.network') }}</NuxtLink>
        <NuxtLink to="/incidents" class="nav-link">{{ t('nav.incidents') }}</NuxtLink>
        <NuxtLink to="/identity" class="nav-link">{{ t('nav.identity') }}</NuxtLink>
      </nav>
    </aside>
    <main class="main-content">
      <NuxtPage />
    </main>
  </div>
</template>

<script setup>
import { useI18n } from '~/composables/useI18n'

const { locale, t, toggleLocale } = useI18n()
</script>

<style scoped>
.lang-toggle {
  display: block;
  width: 100%;
  text-align: left;
  background: rgba(0, 0, 0, 0.25);
  cursor: pointer;
  font: inherit;
}
.lang-toggle:hover {
  color: var(--primary);
  background: rgba(0, 0, 0, 0.4);
}
</style>
