import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { navItems } from '../data/mockData.js'

function AppLayout() {
  const [menuOpen, setMenuOpen] = useState(false)

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
          {navItems.map((item) => (
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
          ))}
        </nav>
      </header>

      <main className="app-main">
        <Outlet />
      </main>

      <footer className="app-footer">
        Secure Vault &mdash; zero-knowledge demo. Data shown is mock data only.
      </footer>
    </div>
  )
}

export default AppLayout
