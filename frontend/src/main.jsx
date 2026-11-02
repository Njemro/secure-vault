
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import App from './App.jsx'
import keycloak from './auth/keycloak'

import { AuthProvider } from './context/AuthContext.jsx'
import { VaultProvider } from './context/VaultContext.jsx'

import './styles.css'

async function bootstrap() {
  const root = createRoot(document.getElementById('root'))

  try {
    await keycloak.init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      checkLoginIframe: false,
    })

    root.render(
      <StrictMode>
        <BrowserRouter>
          <AuthProvider>
            <VaultProvider>
              <App />
            </VaultProvider>
          </AuthProvider>
        </BrowserRouter>
      </StrictMode>,
    )
  } catch (error) {
    console.error('Keycloak initialization failed:', error)

    root.render(
      <div role="alert">
        Servis za autentifikaciju nije dostupan. Provjeri Keycloak i osvježi
        stranicu.
      </div>
    )
  }
}

bootstrap()
