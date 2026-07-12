import { useEffect, useMemo, useState } from 'react';
import { useDataset } from '../context/DatasetContext';
import DependencyGraph from '../components/DependencyGraph';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  Legend
} from 'recharts';
import './Graph.css';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  NONE: '#10b981'
};

export default function Graph() {
  const { getGraphData, getStatsData, activeDataset } = useDataset();
  const [graph, setGraph] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [isFiltersOpen, setIsFiltersOpen] = useState(true);

  // Filters State
  const [search, setSearch] = useState('');
  const [cveSearch, setCveSearch] = useState('');
  const [appFilter, setAppFilter] = useState('');
  const [versionSearch, setVersionSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [minRiskScore, setMinRiskScore] = useState(0);
  const [maxRiskScore, setMaxRiskScore] = useState(100);
  const [depthFilter, setDepthFilter] = useState('');
  const [businessCriticalityFilter, setBusinessCriticalityFilter] = useState('');
  const [licenseTypeFilter, setLicenseTypeFilter] = useState('');
  const [maintenanceFilter, setMaintenanceFilter] = useState('');
  
  const [showOnlyVulnerable, setShowOnlyVulnerable] = useState(false);
  const [showOnlyTransitive, setShowOnlyTransitive] = useState(false);
  const [showOnlyDirect, setShowOnlyDirect] = useState(false);
  const [showOnlyLicenseConflicts, setShowOnlyLicenseConflicts] = useState(false);
  const [showOnlyCriticalPaths, setShowOnlyCriticalPaths] = useState(false);

  // Graph Mode State
  const [graphMode, setGraphMode] = useState('full'); // full, vulnerability, license, heat, business

  // Load initial graph data
  useEffect(() => {
    let isMounted = true;
    async function fetchData() {
      try {
        const graphRes = await getGraphData();
        const statsRes = await getStatsData();
        if (isMounted) {
          setGraph(Array.isArray(graphRes.data) ? graphRes.data : []);
          setStats(statsRes.data);
        }
      } catch (err) {
        console.error('Failed to load dependency graph intelligence data.', err);
      }
    }
    fetchData();
    return () => {
      isMounted = false;
    };
  }, [activeDataset]);

  const handleResetFilters = () => {
    setSearch('');
    setCveSearch('');
    setAppFilter('');
    setVersionSearch('');
    setSeverityFilter('');
    setMinRiskScore(0);
    setMaxRiskScore(100);
    setDepthFilter('');
    setBusinessCriticalityFilter('');
    setLicenseTypeFilter('');
    setMaintenanceFilter('');
    setShowOnlyVulnerable(false);
    setShowOnlyTransitive(false);
    setShowOnlyDirect(false);
    setShowOnlyLicenseConflicts(false);
    setShowOnlyCriticalPaths(false);
  };

  const hasActiveFilters = useMemo(() => {
    return !!(search || cveSearch || appFilter || versionSearch || severityFilter || minRiskScore > 0 || depthFilter !== '' || licenseTypeFilter || maintenanceFilter || showOnlyVulnerable || showOnlyTransitive || showOnlyDirect || showOnlyLicenseConflicts);
  }, [search, cveSearch, appFilter, versionSearch, severityFilter, minRiskScore, depthFilter, licenseTypeFilter, maintenanceFilter, showOnlyVulnerable, showOnlyTransitive, showOnlyDirect, showOnlyLicenseConflicts]);

  // Compute stats metrics dynamically from graph
  const metrics = useMemo(() => {
    const total = graph.length;
    const direct = graph.filter(node => node.depth === 0).length;
    const transitive = graph.filter(node => node.depth > 0).length;
    const vulnerable = graph.filter(node => Array.isArray(node.vulnerabilities) && node.vulnerabilities.length > 0).length;
    const critical = graph.filter(node => 
      node.priority === 'Fix Immediately' || 
      node.vulnerabilities?.some(v => v.severity === 'CRITICAL')
    ).length;
    
    let maxDepth = 0;
    let totalRisk = 0;
    const apps = new Set();

    for (const node of graph) {
      if (node.depth > maxDepth) maxDepth = node.depth;
      totalRisk += node.riskScore || 0;
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(a => apps.add(a));
      }
    }

    const avgRisk = total > 0 ? (totalRisk / total).toFixed(1) : 0;

    return {
      total,
      direct,
      transitive,
      vulnerable,
      critical,
      maxDepth,
      appsCovered: apps.size,
      avgRisk
    };
  }, [graph]);

  // Extract dropdown options dynamically
  const uniqueLicenses = useMemo(() => {
    const licenses = new Set();
    graph.forEach(node => {
      if (node.license) licenses.add(node.license);
    });
    return Array.from(licenses).sort();
  }, [graph]);

  const uniqueApplications = useMemo(() => {
    const apps = new Set();
    graph.forEach(node => {
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(a => apps.add(a));
      }
    });
    return Array.from(apps).sort();
  }, [graph]);

  // Dynamically compute charts analytics
  const chartsData = useMemo(() => {
    // 1. Vulnerability distribution
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    graph.forEach(node => {
      if (Array.isArray(node.vulnerabilities) && node.vulnerabilities.length > 0) {
        let maxSev = 'LOW';
        node.vulnerabilities.forEach(v => {
          const sev = String(v.severity).toUpperCase();
          if (sev === 'CRITICAL') maxSev = 'CRITICAL';
          else if (sev === 'HIGH' && maxSev !== 'CRITICAL') maxSev = 'HIGH';
          else if (sev === 'MEDIUM' && maxSev !== 'CRITICAL' && maxSev !== 'HIGH') maxSev = 'MEDIUM';
        });
        severityCounts[maxSev]++;
      } else {
        severityCounts.NONE++;
      }
    });
    const vulnerabilityDistribution = Object.entries(severityCounts).map(([name, value]) => ({
      name,
      value,
      color: SEVERITY_COLORS[name]
    })).filter(item => item.value > 0);

    // 2. Risk score distribution (buckets of 10)
    const riskBuckets = Array.from({ length: 10 }, (_, i) => ({
      range: `${i * 10}-${(i + 1) * 10}`,
      count: 0
    }));
    graph.forEach(node => {
      const score = node.riskScore || 0;
      const index = Math.min(Math.floor(score / 10), 9);
      riskBuckets[index].count++;
    });

    // 3. License distribution (top 5)
    const licenseCounts = {};
    graph.forEach(node => {
      const lic = node.license || 'Unknown';
      licenseCounts[lic] = (licenseCounts[lic] || 0) + 1;
    });
    const licenseDistribution = Object.entries(licenseCounts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // 4. Dependency depth distribution
    const depthCounts = {};
    graph.forEach(node => {
      const d = node.depth ?? 0;
      depthCounts[d] = (depthCounts[d] || 0) + 1;
    });
    const depthDistribution = Object.entries(depthCounts).map(([depth, count]) => ({
      depth: `Depth ${depth}`,
      count
    }));

    // 5. Top 10 riskiest packages
    const topRiskiest = [...graph]
      .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))
      .slice(0, 10)
      .map(node => ({
        name: node.name,
        score: node.riskScore || 0
      }));

    // 6. Application risk comparison
    const appRiskSum = {};
    const appRiskCount = {};
    graph.forEach(node => {
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(app => {
          appRiskSum[app] = (appRiskSum[app] || 0) + (node.riskScore || 0);
          appRiskCount[app] = (appRiskCount[app] || 0) + 1;
        });
      }
    });
    const appRiskComparison = Object.entries(appRiskSum).map(([name, sum]) => ({
      name,
      avgRisk: Number((sum / appRiskCount[name]).toFixed(1))
    })).sort((a, b) => b.avgRisk - a.avgRisk);

    return {
      vulnerabilityDistribution,
      riskBuckets,
      licenseDistribution,
      depthDistribution,
      topRiskiest,
      appRiskComparison
    };
  }, [graph]);

  return (
    <div className="page-placeholder--graph">
      {/* Cybersecurity Dashboard Header */}
      <header className="graph-header">
        <div className="graph-header__title">
          <h1>Dependency Graph Intelligence</h1>
          <p>
            Explore direct and transitive dependencies, uncover hidden attack paths, and understand software supply-chain risk propagation.
          </p>
        </div>
      </header>

      {/* Top summary stats insight cards */}
      <section className="insight-grid">
        <article className="insight-card">
          <span className="insight-card__label">Total Packages</span>
          <strong className="insight-card__value">{metrics.total}</strong>
          <span className="insight-card__trend">Resolved in BOM</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Direct Dependencies</span>
          <strong className="insight-card__value">{metrics.direct}</strong>
          <span className="insight-card__trend">Declared directly</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Transitive Dependencies</span>
          <strong className="insight-card__value">{metrics.transitive}</strong>
          <span className="insight-card__trend">Deep dependency tree</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Vulnerable Packages</span>
          <strong className="insight-card__value" style={{ color: '#ef4444' }}>{metrics.vulnerable}</strong>
          <span className="insight-card__trend">Matches vulnerability DB</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Critical Packages</span>
          <strong className="insight-card__value" style={{ color: '#dc2626' }}>{metrics.critical}</strong>
          <span className="insight-card__trend">Requires immediate fix</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Max Dependency Depth</span>
          <strong className="insight-card__value">{metrics.maxDepth}</strong>
          <span className="insight-card__trend">Depth layer max</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Applications Covered</span>
          <strong className="insight-card__value">{metrics.appsCovered}</strong>
          <span className="insight-card__trend">Microservices & APIs</span>
        </article>
        <article className="insight-card">
          <span className="insight-card__label">Average Risk Score</span>
          <strong className="insight-card__value" style={{ color: '#7c3aed' }}>{metrics.avgRisk}</strong>
          <span className="insight-card__trend">Avg risk posture</span>
        </article>
      </section>

      {/* Advanced Collapsible Filter Panel */}
      <section className="filter-panel">
        <div className="filter-panel__header" onClick={() => setIsFiltersOpen(!isFiltersOpen)}>
          <h2>
            Advanced Filters
            {hasActiveFilters && <span className="badge-count" style={{ marginLeft: '8px' }}>Active</span>}
          </h2>
          <span className={`filter-panel__toggle-icon ${isFiltersOpen ? 'is-open' : ''}`}>▼</span>
        </div>

        {isFiltersOpen && (
          <div className="filter-panel__content">
            <div className="filter-panel__row">
              <div className="filter-field">
                <label htmlFor="search-pkg">Package Name</label>
                <input
                  id="search-pkg"
                  type="text"
                  className="filter-input"
                  placeholder="Search package..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                />
              </div>

              <div className="filter-field">
                <label htmlFor="search-cve">CVE ID</label>
                <input
                  id="search-cve"
                  type="text"
                  className="filter-input"
                  placeholder="e.g. CVE-2022-1085"
                  value={cveSearch}
                  onChange={e => setCveSearch(e.target.value)}
                />
              </div>

              <div className="filter-field">
                <label htmlFor="filter-app">Application</label>
                <select
                  id="filter-app"
                  className="filter-select"
                  value={appFilter}
                  onChange={e => setAppFilter(e.target.value)}
                >
                  <option value="">All Applications</option>
                  {uniqueApplications.map(app => (
                    <option key={app} value={app}>{app}</option>
                  ))}
                </select>
              </div>

              <div className="filter-field">
                <label htmlFor="search-ver">Version</label>
                <input
                  id="search-ver"
                  type="text"
                  className="filter-input"
                  placeholder="Search version..."
                  value={versionSearch}
                  onChange={e => setVersionSearch(e.target.value)}
                />
              </div>
            </div>

            <div className="filter-panel__row">
              <div className="filter-field">
                <label htmlFor="filter-severity">Severity</label>
                <select
                  id="filter-severity"
                  className="filter-select"
                  value={severityFilter}
                  onChange={e => setSeverityFilter(e.target.value)}
                >
                  <option value="">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="filter-field">
                <label htmlFor="risk-slider">Min Risk Score ({minRiskScore})</label>
                <input
                  id="risk-slider"
                  type="range"
                  min="0"
                  max="100"
                  value={minRiskScore}
                  onChange={e => setMinRiskScore(Number(e.target.value))}
                  style={{ accentColor: '#8b5cf6' }}
                />
              </div>

              <div className="filter-field">
                <label htmlFor="filter-depth">Dependency Depth</label>
                <input
                  id="filter-depth"
                  type="number"
                  className="filter-input"
                  placeholder="e.g. 1"
                  value={depthFilter}
                  onChange={e => setDepthFilter(e.target.value)}
                />
              </div>

              <div className="filter-field">
                <label htmlFor="filter-license">License Type</label>
                <select
                  id="filter-license"
                  className="filter-select"
                  value={licenseTypeFilter}
                  onChange={e => setLicenseTypeFilter(e.target.value)}
                >
                  <option value="">All Licenses</option>
                  {uniqueLicenses.map(lic => (
                    <option key={lic} value={lic}>{lic}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="filter-panel__row">
              <div className="filter-field">
                <label htmlFor="filter-maintenance">Maintenance Level</label>
                <select
                  id="filter-maintenance"
                  className="filter-select"
                  value={maintenanceFilter}
                  onChange={e => setMaintenanceFilter(e.target.value)}
                >
                  <option value="">All Statuses</option>
                  <option value="High">Unmaintained</option>
                  <option value="Low">Actively Maintained</option>
                </select>
              </div>

              <div className="filter-checkbox-group">
                <label className="filter-checkbox">
                  <input
                    type="checkbox"
                    checked={showOnlyVulnerable}
                    onChange={e => setShowOnlyVulnerable(e.target.checked)}
                  />
                  Vulnerable Only
                </label>

                <label className="filter-checkbox">
                  <input
                    type="checkbox"
                    checked={showOnlyTransitive}
                    onChange={e => setShowOnlyTransitive(e.target.checked)}
                  />
                  Transitive Only
                </label>

                <label className="filter-checkbox">
                  <input
                    type="checkbox"
                    checked={showOnlyDirect}
                    onChange={e => setShowOnlyDirect(e.target.checked)}
                  />
                  Direct Only
                </label>

                <label className="filter-checkbox">
                  <input
                    type="checkbox"
                    checked={showOnlyLicenseConflicts}
                    onChange={e => setShowOnlyLicenseConflicts(e.target.checked)}
                  />
                  License Conflicts
                </label>
              </div>

              <button className="btn-reset" onClick={handleResetFilters}>
                Reset Filters
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Main visualization area */}
      <section className="vis-container">
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {/* Graph Modes Toggle */}
          <div className="graph-modes-bar">
            <button
              className={`graph-mode-btn ${graphMode === 'full' ? 'is-active' : ''}`}
              onClick={() => setGraphMode('full')}
            >
              Full Map
            </button>
            <button
              className={`graph-mode-btn ${graphMode === 'vulnerability' ? 'is-active' : ''}`}
              onClick={() => setGraphMode('vulnerability')}
            >
              Vulnerability Propagation
            </button>
            <button
              className={`graph-mode-btn ${graphMode === 'license' ? 'is-active' : ''}`}
              onClick={() => setGraphMode('license')}
            >
              License Conflict Map
            </button>
            <button
              className={`graph-mode-btn ${graphMode === 'heat' ? 'is-active' : ''}`}
              onClick={() => setGraphMode('heat')}
            >
              Risk Heat Map
            </button>
            <button
              className={`graph-mode-btn ${graphMode === 'business' ? 'is-active' : ''}`}
              onClick={() => setGraphMode('business')}
            >
              Business Impact Map
            </button>
          </div>

          <DependencyGraph
            graph={graph}
            filters={{
              search,
              cveSearch,
              appFilter,
              versionSearch,
              severityFilter,
              minRiskScore,
              maxRiskScore,
              depthFilter,
              businessCriticalityFilter,
              licenseTypeFilter,
              maintenanceFilter,
              showOnlyVulnerable,
              showOnlyTransitive,
              showOnlyDirect,
              showOnlyLicenseConflicts,
              showOnlyCriticalPaths
            }}
            graphMode={graphMode}
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
          />
        </div>

        {/* Right Detail Sidebar */}
        {selectedNode && (
          <aside className="details-sidebar">
            <div className="details-sidebar__header">
              <h2>Risk Profile</h2>
              <button className="btn-close" onClick={() => setSelectedNode(null)}>
                &times;
              </button>
            </div>
            <div className="details-sidebar__content">
              {/* Package info */}
              <div className="details-section">
                <h3>Package Metadata</h3>
                <div className="details-grid">
                  <div className="details-item">
                    <label>Package Name</label>
                    <span>{selectedNode.name}</span>
                  </div>
                  <div className="details-item">
                    <label>Version</label>
                    <span>{selectedNode.version}</span>
                  </div>
                  <div className="details-item">
                    <label>Risk Score</label>
                    <span style={{ color: selectedNode.riskScore >= 70 ? '#ef4444' : selectedNode.riskScore >= 40 ? '#f59e0b' : '#10b981' }}>
                      {selectedNode.riskScore}
                    </span>
                  </div>
                  <div className="details-item">
                    <label>Priority</label>
                    <span>{selectedNode.priority}</span>
                  </div>
                  <div className="details-item">
                    <label>License</label>
                    <span>{selectedNode.license || 'Unknown'}</span>
                  </div>
                  <div className="details-item">
                    <label>Last Updated</label>
                    <span>{selectedNode.lastUpdated || 'Unknown'}</span>
                  </div>
                </div>
              </div>

              {/* AI Security Narrative */}
              <div className="details-section">
                <h3>⚡ AI Security Narrative</h3>
                <p style={{ fontSize: '0.82rem', color: '#1e293b', lineHeight: 1.5, margin: 0 }}>
                  {selectedNode.securityNarrative}
                </p>
              </div>

              {/* AI Attack Path Analysis */}
              <div className="details-section">
                <h3>⛓️ AI Attack Path Analysis</h3>
                <p style={{ fontSize: '0.82rem', color: '#1e293b', lineHeight: 1.5, marginBottom: '6px' }}>
                  {selectedNode.attackAnalysis?.chainExplanation}
                </p>
                <div style={{ maxHeight: '90px', overflowY: 'auto', background: 'rgba(139,92,246,0.05)', padding: '6px', borderRadius: '6px' }}>
                  {selectedNode.dependencyPaths?.map((p, i) => (
                    <div key={i} className="mono" style={{ fontSize: '0.7rem', padding: '2px 0' }}>
                      {p.join(' → ')}
                    </div>
                  ))}
                </div>
              </div>

              {/* AI Risk Score Explainer */}
              <div className="details-section">
                <h3>📊 AI Risk Score Explainer</h3>
                <p style={{ fontSize: '0.82rem', color: '#1e293b', lineHeight: 1.5, marginBottom: '6px' }}>
                  {selectedNode.riskExplanation?.finalScoreExplanation}
                </p>
                <div className="details-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: '6px', fontSize: '0.72rem' }}>
                  <div>Base risk: <strong>+{selectedNode.riskExplanation?.vulnerabilityContribution || 0}</strong></div>
                  <div>Exploitability: <strong>+{selectedNode.riskExplanation?.exploitabilityContribution || 0}</strong></div>
                  <div>Maintenance: <strong>+{selectedNode.riskExplanation?.maintenanceContribution || 0}</strong></div>
                  <div>License: <strong>+{selectedNode.riskExplanation?.licenseContribution || 0}</strong></div>
                  <div>Paths count: <strong>{selectedNode.pathCount || 1} ({selectedNode.pathRiskMultiplier || 1.0}x)</strong></div>
                  <div>Compounded: <strong>{selectedNode.compoundedRisk || selectedNode.riskScore}</strong></div>
                </div>
              </div>

              {/* AI Business Impact */}
              <div className="details-section">
                <h3>🏢 AI Business Impact</h3>
                <p style={{ fontSize: '0.82rem', color: '#1e293b', lineHeight: 1.5, margin: 0 }}>
                  {selectedNode.businessImpact?.impactNarrative}
                </p>
                <div className="details-grid" style={{ gridTemplateColumns: '1fr 1fr', marginTop: '6px', fontSize: '0.72rem' }}>
                  <div>Impact rating: <strong>{selectedNode.businessImpact?.impactLevel}</strong></div>
                  <div>Blast Score: <strong>{selectedNode.businessImpact?.blastRadius}</strong></div>
                </div>
              </div>

              {/* AI Remediation Advice */}
              <div className="details-section">
                <h3>🛠️ AI Remediation Advice</h3>
                <div className="details-grid" style={{ gridTemplateColumns: '1fr 1fr', marginBottom: '6px' }}>
                  <div>Action: <strong>{selectedNode.remediation?.immediateAction}</strong></div>
                  <div>Urgency: <strong>{selectedNode.remediation?.urgency}</strong></div>
                </div>
                <p style={{ fontSize: '0.82rem', color: '#1e293b', lineHeight: 1.5, marginBottom: '6px' }}>
                  {selectedNode.remediation?.remediationNarrative}
                </p>
                <div style={{ fontSize: '0.75rem', background: '#f8fafc', padding: '6px', borderRadius: '4px', border: '1px solid rgba(0,0,0,0.05)' }}>
                  <strong>Copilot:</strong> {selectedNode.remediation?.recommendation}
                </div>
              </div>

              {/* Security panel */}
              <div className="details-section">
                <h3>Vulnerabilities</h3>
                {Array.isArray(selectedNode.vulnerabilities) && selectedNode.vulnerabilities.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {selectedNode.vulnerabilities.map((vuln, i) => (
                      <div key={i} className="vuln-item">
                        <div className="vuln-item__header">
                          <span className="vuln-item__cve">{vuln.cveId}</span>
                          <span className="vuln-item__score">CVSS {vuln.cvssScore}</span>
                        </div>
                        <p className="vuln-item__desc">{vuln.description}</p>
                        <div style={{ fontSize: '0.75rem', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <div><strong>Exploitability:</strong> {vuln.exploitability || 'UNKNOWN'}</div>
                          {vuln.fixedVersion && (
                            <div style={{ color: '#7c3aed' }}>
                              <strong>Recommendation:</strong> Upgrade to v{vuln.fixedVersion}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span style={{ fontSize: '0.85rem', color: '#475569' }}>No vulnerabilities detected.</span>
                )}
              </div>
            </div>

            <div className="details-actions">
              <button
                className="btn-action btn-action--primary"
                onClick={() => {
                  alert(`Reporting security audit for ${selectedNode.name}@${selectedNode.version}. PDF/JSON report generated successfully.`);
                }}
              >
                Export Package Audit
              </button>
            </div>
          </aside>
        )}
      </section>

      {/* Analytics Charts Section */}
      <section className="charts-section">
        {/* Vulnerability Distribution */}
        <div className="chart-card">
          <h3>Vulnerability Distribution</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={chartsData.vulnerabilityDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {chartsData.vulnerabilityDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }}
                  itemStyle={{ color: '#0f172a' }}
                />
                <Legend formatter={(value) => <span style={{ color: '#475569', fontSize: '0.75rem' }}>{value}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Score Distribution */}
        <div className="chart-card">
          <h3>Risk Score Distribution</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <AreaChart data={chartsData.riskBuckets}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="range" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="count" stroke="#8b5cf6" strokeWidth={2} fillOpacity={1} fill="url(#colorRisk)" name="Packages Count" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top licenses */}
        <div className="chart-card">
          <h3>Top Licenses</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={chartsData.licenseDistribution}>
                <XAxis dataKey="name" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Packages count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top 10 Riskiest */}
        <div className="chart-card">
          <h3>Top 10 Riskiest Packages</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={chartsData.topRiskiest} layout="vertical">
                <XAxis type="number" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis dataKey="name" type="category" stroke="#64748b" style={{ fontSize: '0.75rem' }} width={80} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Bar dataKey="score" fill="#ef4444" radius={[0, 4, 4, 0]} name="Risk score" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>
    </div>
  );
}
