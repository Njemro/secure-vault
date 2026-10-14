import { Routes, Route } from 'react-router-dom'
import AppLayout from './components/AppLayout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import MySecrets from './pages/MySecrets.jsx'
import SharedWithMe from './pages/SharedWithMe.jsx'
import SecuritySettings from './pages/SecuritySettings.jsx'
import NotFound from './pages/NotFound.jsx'

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="my-secrets" element={<MySecrets />} />
        <Route path="shared-with-me" element={<SharedWithMe />} />
        <Route path="security-settings" element={<SecuritySettings />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
