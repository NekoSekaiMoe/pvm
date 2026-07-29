export default defineNuxtConfig({
  compatibilityDate: '2024-04-03',
  devtools: { enabled: true },
  ssr: false,
  css: ['~/assets/css/main.css'],
  app: {
    head: {
      title: 'PVM - Container Manager'
    }
  }
})
