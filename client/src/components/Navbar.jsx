import './Navbar.css';

export default function Navbar() {
  return (
    <header className="navbar">
      <div className="navbar__title">
        <p className="navbar__eyebrow">Dashboard</p>
        <h1>Dashboard</h1>
        <p>Supply chain exposure, prioritization, and remediation in one place.</p>
      </div>

      <label className="navbar__search" aria-label="Search something here">
        <span className="navbar__search-icon" aria-hidden="true">⌕</span>
        <input type="search" placeholder="Search something here..." />
      </label>

      <div className="navbar__actions">
        <button type="button" className="navbar__icon-button" aria-label="Messages">
          💬
          <span className="navbar__badge">10</span>
        </button>
        <button type="button" className="navbar__icon-button" aria-label="Notifications">
          🔔
          <span className="navbar__badge">52</span>
        </button>

        <div className="navbar__profile">
          <div className="navbar__avatar">OD</div>
          <div>
            <strong>Oda Dink</strong>
            <span>Super Admin</span>
          </div>
        </div>
      </div>
    </header>
  );
}
