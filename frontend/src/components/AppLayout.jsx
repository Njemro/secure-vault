import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import './AppLayout.css'

const navItems = [
  { label: 'Dashboard', to: '/dashboard', end: true },
  { label: 'My Secrets', to: '/secrets', end: true },
  { label: 'Shared With Me', to: '/shared', end: true },
  { label: 'Security Settings', to: '/security', end: true },
]

function AppLayout() {
  const { user, signOut } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)

async function handleLogout() {
  await signOut()
}

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header__bar">
          <NavLink to="/dashboard" className="app-brand">
            <span className="app-brand__mark" aria-hidden="true">
              &#128274;
            </span>
            Secure Vault
          </NavLink>

          <button
            type="button"
            className="app-menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="app-nav"
            aria-label={menuOpen ? 'Zatvori meni' : 'Otvori meni'}
            onClick={() => setMenuOpen((open) => !open)}
          >
            &#9776;
          </button>
        </div>

        <nav
          id="app-nav"
          className={`app-nav ${menuOpen ? 'app-nav--open' : ''}`}
          aria-label="Glavna navigacija"
        >
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) =>
                isActive
                  ? 'app-nav__link app-nav__link--active'
                  : 'app-nav__link'
              }
            >
              {item.label}
            </NavLink>
          ))}

          <button
            type="button"
            className="app-nav__link app-nav__logout"
            onClick={handleLogout}
          >
            Logout
          </button>
        </nav>
      </header>

      <main className="app-main">
        <Outlet />
      </main>

      <footer className="app-footer">
        Secure Vault — zero-knowledge.
        {user?.preferred_username? ` Signed in as ${user.preferred_username}` : ''}
      </footer>
    </div>
  )
}

export default AppLayout
