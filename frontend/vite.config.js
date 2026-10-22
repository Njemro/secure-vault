import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Forward API calls to the Spring Cloud Gateway during local development.
    // No concrete API endpoints are defined yet; this only wires the prefix so
    // future client code can call same-origin "/api/..." without CORS issues.
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
