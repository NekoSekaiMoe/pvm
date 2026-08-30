<template>
  <div>
    <h1>{{ t('pages.incidents.title') }}</h1>
    <p class="muted">{{ t('pages.incidents.subtitle') }}</p>

    <!-- Decision Matrix -->
    <div class="glass-card">
      <h3>{{ t('pages.incidents.matrixTitle') }}</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>{{ t('pages.incidents.colTier') }}</th>
              <th>{{ t('pages.incidents.colTrigger') }}</th>
              <th>{{ t('pages.incidents.colAction') }}</th>
              <th>{{ t('pages.incidents.colPreserve') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><span class="pill allow">{{ t('pages.incidents.tierLow') }}</span></td>
              <td>{{ t('pages.incidents.trigLow') }}</td>
              <td><span class="pill block">ActionBlock</span></td>
              <td>{{ t('pages.incidents.preserveLow') }}</td>
            </tr>
            <tr>
              <td><span class="pill constrain">{{ t('pages.incidents.tierMedium') }}</span></td>
              <td>{{ t('pages.incidents.trigMedium') }}</td>
              <td><span class="pill approve">ActionPause</span></td>
              <td>{{ t('pages.incidents.preserveMedium') }}</td>
            </tr>
            <tr>
              <td><span class="pill deny">{{ t('pages.incidents.tierHigh') }}</span></td>
              <td>{{ t('pages.incidents.trigHigh') }}</td>
              <td><span class="pill revoke">ActionQuarantine</span></td>
              <td>{{ t('pages.incidents.preserveHigh') }}</td>
            </tr>
            <tr>
              <td><span class="pill deny" style="background:rgba(220,38,38,0.4);">{{ t('pages.incidents.tierCritical') }}</span></td>
              <td>{{ t('pages.incidents.trigCritical') }}</td>
              <td><span class="pill deny">ActionTerminate</span></td>
              <td>{{ t('pages.incidents.preserveCritical') }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Escalation Rules -->
    <div class="glass-card">
      <h3>{{ t('pages.incidents.escalationTitle') }}</h3>
      <p class="muted" style="margin-bottom:1rem;">{{ t('pages.incidents.escalationText') }}</p>

      <div class="stat-grid">
        <div class="stat-tile">
          <div class="stat-value">3</div>
          <div class="stat-label">{{ t('pages.incidents.statThreshold') }}</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">RevokeAll</div>
          <div class="stat-label">{{ t('pages.incidents.statRevoke') }}</div>
        </div>
        <div class="stat-tile">
          <div class="stat-value">SHA-256</div>
          <div class="stat-label">{{ t('pages.incidents.statSha') }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()
</script>
