import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const gateway = 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: gateway, changeOrigin: false, secure: false },
      '/auth': { target: gateway, changeOrigin: false, secure: false },
      '/oauth2': { target: gateway, changeOrigin: false, secure: false },
      '/login/oauth2': { target: gateway, changeOrigin: false, secure: false },
      '/logout': { target: gateway, changeOrigin: false, secure: false },
    },
  },
})
