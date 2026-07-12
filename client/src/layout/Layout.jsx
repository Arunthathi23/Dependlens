import { NavLink, Outlet } from 'react-router-dom';
import './Layout.css';

const navigationItems = [
  { label: 'Dashboard', icon: 'D', to: '/' },
  { label: 'Dependency Graph', icon: 'G', to: '/graph' },
  { label: 'Findings', icon: 'F', to: '/findings' },
  { label: 'Validation', icon: 'V', to: '/validation' },
];

export default function Layout() {
  return (
    <div className="app-shell">
      <aside className="app-shell__sidebar">
        <div className="app-shell__brand">
          <div className="app-shell__brand-mark">DL</div>
          <div>
            <h1>DependLens</h1>
            <p>Supply chain intelligence</p>
          </div>
        </div>

        <nav className="app-shell__nav" aria-label="Primary navigation">
          {navigationItems.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `app-shell__nav-item${isActive ? ' app-shell__nav-item--active' : ''}`}
            >
              <span className="app-shell__nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
              <span className="app-shell__nav-indicator" aria-hidden="true" />
            </NavLink>
          ))}
        </nav>

        <div className="app-shell__sidebar-footnote">
          <span>Enterprise readiness</span>
          <strong>Live security posture</strong>
        </div>
      </aside>

      <main className="app-shell__content">
        <Outlet />
      </main>
    </div>
  );
}
