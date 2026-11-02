import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './context/AuthContext.jsx'

import AppLayout from './components/AppLayout.jsx'
import {
  RequireSetupKeys,
  RequireUnlockedVault,
} from './components/VaultRouteGuards.jsx'

import Login from './pages/Login'
import Register from './pages/Register'
import SetupKeys from './pages/setupKeys'
import UnlockVault from './pages/UnlockVault'
import Dashboard from './pages/Dashboard'
import MySecrets from './pages/MySecrets'
import SharedWithMe from './pages/SharedWithMe'
import SecuritySettings from './pages/SecuritySettings'
import NotFound from './pages/NotFound'
import CreateSecret from './pages/CreateSecret.jsx'
import EditSecret from './pages/EditSecret.jsx'
import SecretDetail from './pages/SecretDetail.jsx'

function RequireAuth({ children }) {
  const { authenticated } = useAuth()

  return authenticated
    ? children
    : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route
        path="/"
        element={<Navigate to="/dashboard" replace />}
      />

      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route
        path="/setup-keys"
        element={
          <RequireAuth>
            <RequireSetupKeys>
              <SetupKeys />
            </RequireSetupKeys>
          </RequireAuth>
        }
      />

      <Route
        path="/unlock-vault"
        element={
          <RequireAuth>
            <UnlockVault />
          </RequireAuth>
        }
      />

      <Route
        element={
          <RequireAuth>
            <RequireUnlockedVault>
              <AppLayout />
            </RequireUnlockedVault>
          </RequireAuth>
        }
      >
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/secrets" element={<MySecrets />} />
        <Route path="/secrets/new" element={<CreateSecret />} />
        <Route path="/secrets/:id" element={<SecretDetail />} />
        <Route path="/secrets/:id/edit" element={<EditSecret />} />
        <Route path="/shared" element={<SharedWithMe />} />
        <Route path="/security" element={<SecuritySettings />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}