import { NavLink, Outlet } from 'react-router-dom';
import { useDataset } from '../context/DatasetContext';
import './Layout.css';

const navigationItems = [
  { label: 'Dashboard', icon: 'D', to: '/' },
  { label: 'Dependency Graph', icon: 'G', to: '/graph' },
  { label: 'Findings', icon: 'F', to: '/findings' },
  { label: 'Upload SBOM', icon: 'U', to: '/upload' },
];

export default function Layout() {
  const { activeDataset, resetDataset } = useDataset();

  const handleResetClick = async () => {
    try {
      await resetDataset();
      alert("Successfully restored sample dataset.");
      window.location.reload();
    } catch (err) {
      alert("Reset failed: " + err.message);
    }
  };

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

        <div style={{ padding: '16px', borderTop: '1px solid rgba(255,255,255,0.08)', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{
            fontSize: '0.75rem',
            fontWeight: 'bold',
            padding: '6px 10px',
            borderRadius: '6px',
            textAlign: 'center',
            background: activeDataset === 'uploaded' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            color: activeDataset === 'uploaded' ? '#10b981' : '#f87171',
            border: activeDataset === 'uploaded' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)'
          }}>
            {activeDataset === 'uploaded' ? 'Using Uploaded Dataset' : 'Using Sample Dataset'}
          </div>

          {activeDataset === 'uploaded' && (
            <button
              onClick={handleResetClick}
              style={{
                fontSize: '0.75rem',
                fontWeight: 'bold',
                padding: '8px',
                borderRadius: '6px',
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid rgba(255,255,255,0.1)',
                color: '#cbd5e1',
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
              onMouseEnter={e => { e.target.style.background = 'rgba(239,68,68,0.2)'; e.target.style.color = '#ffffff'; }}
              onMouseLeave={e => { e.target.style.background = 'rgba(255,255,255,0.05)'; e.target.style.color = '#cbd5e1'; }}
            >
              Reset to Sample Dataset
            </button>
          )}
        </div>

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
