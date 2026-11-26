
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

const certsPath = path.resolve(import.meta.dirname, '../certs');

const ca = fs.readFileSync(
  path.join(certsPath, 'rootCA.pem')
);

export default defineConfig({
  plugins: [react()],

  server: {
    host: 'localhost',
    port: 5173,

    https: {
      key: fs.readFileSync(
        path.join(certsPath, 'localhost-key.pem')
      ),
      cert: fs.readFileSync(
        path.join(certsPath, 'localhost.pem')
      )
    },

    proxy: {
      '/api': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: true,
        ca
      },
      '/auth': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: true,
        ca
      },
      '/oauth2': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: true,
        ca
      },
      '/login/oauth2/code/keycloak': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: true
      },
      '/logout': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: true,
        ca
      }
    }
  }
});
