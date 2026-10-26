import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext.jsx'
import { VaultProvider } from './context/VaultContext.jsx'
import AppLayout from './components/AppLayout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import MySecrets from './pages/MySecrets.jsx'
import SharedWithMe from './pages/SharedWithMe.jsx'
import SecuritySettings from './pages/SecuritySettings.jsx'
import Register from './pages/Register.jsx'
import Login from './pages/Login.jsx'
import CreateSecret from './pages/CreateSecret.jsx'
import SecretDetail from './pages/SecretDetail.jsx'
import EditSecret from './pages/EditSecret.jsx'
import NotFound from './pages/NotFound.jsx'

export default function App() {
  return (
    <AuthProvider>
      <VaultProvider>
        <Routes>
          <Route path="register" element={<Register />} />
          <Route path="login" element={<Login />} />
          <Route element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="my-secrets" element={<MySecrets />} />
            <Route path="shared-with-me" element={<SharedWithMe />} />
            <Route path="security-settings" element={<SecuritySettings />} />
            <Route path="create-secret" element={<CreateSecret />} />
            <Route path="secrets/:id" element={<SecretDetail />} />
            <Route path="secrets/:id/edit" element={<EditSecret />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </VaultProvider>
    </AuthProvider>
  )
}
