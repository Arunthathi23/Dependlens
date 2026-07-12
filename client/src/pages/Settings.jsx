import './Settings.css';

export default function Settings() {
  return (
    <section className="page-placeholder page-placeholder--settings">
      <div className="page-placeholder__heading">
        <p className="page-placeholder__eyebrow">Settings</p>
        <h1>Workspace preferences</h1>
        <p>Quiet controls for the DependLens experience.</p>
      </div>

      <section className="page-placeholder__panel page-placeholder__settings-panel">
        <div className="settings-grid">
          <label>
            <span>Workspace name</span>
            <input type="text" defaultValue="DependLens" />
          </label>

          <label>
            <span>Notification level</span>
            <select defaultValue="high">
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>

          <label>
            <span>Auto refresh</span>
            <select defaultValue="on">
              <option value="on">On</option>
              <option value="off">Off</option>
            </select>
          </label>

          <label>
            <span>Theme</span>
            <select defaultValue="light">
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
        </div>
      </section>
    </section>
  );
}
