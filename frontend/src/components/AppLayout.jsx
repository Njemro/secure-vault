import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

// Static navigation items (UI configuration, not API data).
const navItems = [
  { label: 'Dashboard', to: '/', end: true },
  { label: 'My Secrets', to: '/my-secrets', end: true },
  { label: 'Shared With Me', to: '/shared-with-me', end: true },
  { label: 'Create Secret', to: '/create-secret', end: true },
  { label: 'Security Settings', to: '/security-settings', end: true },
  { label: 'Logout', to: '/logout', end: true },
]

function AppLayout() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)

  const handleLogout = () => {
    signOut()
    navigate('/login', { replace: true })
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header__bar">
          <span className="app-brand">
            <span className="app-brand__mark" aria-hidden="true">
              &#128274;
            </span>
            Secure Vault
          </span>
          <button
            type="button"
            className="app-menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="app-nav"
            onClick={() => setMenuOpen((open) => !open)}
          >
            &#9776;
          </button>
        </div>
        <nav
          id="app-nav"
          className={`app-nav ${menuOpen ? 'app-nav--open' : ''}`}
          aria-label="Primary"
        >
          {navItems.map((item) => {
            if (item.label === 'Logout') {
              return (
                <button
                  key={item.label}
                  onClick={handleLogout}
                  className={({ isActive }) =>
                    isActive ? 'app-nav__link app-nav__link--active' : 'app-nav__link'
                  }
                >
                  {item.label}
                </button>
              )
            }
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  isActive ? 'app-nav__link app-nav__link--active' : 'app-nav__link'
                }
                onClick={() => setMenuOpen(false)}
              >
                {item.label}
              </NavLink>
            )
          })}
        </nav>
      </header>

      <main className="app-main">
        <Outlet />
      </main>

      <footer className="app-footer">
        Secure Vault &mdash; zero-knowledge. {user ? `Signed in as {user.username}` : ''}
      </footer>
    </div>
  )
}

export default AppLayout
