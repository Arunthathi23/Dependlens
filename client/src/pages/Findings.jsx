import { useEffect, useMemo, useState } from 'react';
import { getGraph, getStats } from '../services/api';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  AreaChart,
  Area
} from 'recharts';
import './Findings.css';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  SAFE: '#10b981'
};

const MAINTENANCE_COLORS = {
  Healthy: '#10b981',
  Aging: '#fbbf24',
  Stale: '#f97316',
  Unmaintained: '#ef4444'
};

export default function Findings() {
  const [graph, setGraph] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isFiltersOpen, setIsFiltersOpen] = useState(true);
  
  // Expanded rows state
  const [expandedIds, setExpandedIds] = useState(new Set());

  // Filters state
  const [search, setSearch] = useState('');
  const [cveSearch, setCveSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [appFilter, setAppFilter] = useState('');
  const [depTypeFilter, setDepTypeFilter] = useState('');
  const [licenseRiskFilter, setLicenseRiskFilter] = useState('');
  const [maintenanceFilter, setMaintenanceFilter] = useState('');
  const [minRiskScore, setMinRiskScore] = useState(0);

  // Checkbox Toggles
  const [onlyCritical, setOnlyCritical] = useState(false);
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);
  const [onlyTransitive, setOnlyTransitive] = useState(false);
  const [onlyDirect, setOnlyDirect] = useState(false);
  const [onlyLicenseConflicts, setOnlyLicenseConflicts] = useState(false);
  const [onlyUnmaintained, setOnlyUnmaintained] = useState(false);

  // NEW ANOMALIES FILTERS
  const [onlyConflicts, setOnlyConflicts] = useState(false);
  const [onlyDiamonds, setOnlyDiamonds] = useState(false);
  const [onlyHighExploitability, setOnlyHighExploitability] = useState(false);
  const [onlyPatchAvailable, setOnlyPatchAvailable] = useState(false);
  const [onlyNoPatchAvailable, setOnlyNoPatchAvailable] = useState(false);
  const [onlyHighBlastRadius, setOnlyHighBlastRadius] = useState(false);

  // FEATURE 1 & 3 & 4 & 5 FILTERS
  const [onlyAging, setOnlyAging] = useState(false);
  const [onlyStale, setOnlyStale] = useState(false);
  const [onlyMultiplePaths, setOnlyMultiplePaths] = useState(false);
  const [popularityLevelFilter, setPopularityLevelFilter] = useState('');
  const [importanceLevelFilter, setImportanceLevelFilter] = useState('');

  // Sorting state
  const [sortKey, setSortKey] = useState('riskScore');
  const [sortDirection, setSortDirection] = useState('desc');

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Load Graph data
  useEffect(() => {
    let isMounted = true;
    async function fetchData() {
      try {
        setLoading(true);
        const graphRes = await getGraph();
        const statsRes = await getStats();
        if (isMounted) {
          setGraph(Array.isArray(graphRes.data) ? graphRes.data : []);
          setStats(statsRes.data);
        }
      } catch (err) {
        console.error('Failed to load findings data.', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    fetchData();
    return () => {
      isMounted = false;
    };
  }, []);

  const handleResetFilters = () => {
    setSearch('');
    setCveSearch('');
    setSeverityFilter('');
    setAppFilter('');
    setDepTypeFilter('');
    setLicenseRiskFilter('');
    setMaintenanceFilter('');
    setMinRiskScore(0);
    setOnlyCritical(false);
    setOnlyVulnerable(false);
    setOnlyTransitive(false);
    setOnlyDirect(false);
    setOnlyLicenseConflicts(false);
    setOnlyUnmaintained(false);
    setOnlyConflicts(false);
    setOnlyDiamonds(false);
    setOnlyHighExploitability(false);
    setOnlyPatchAvailable(false);
    setOnlyNoPatchAvailable(false);
    setOnlyHighBlastRadius(false);
    
    setOnlyAging(false);
    setOnlyStale(false);
    setOnlyMultiplePaths(false);
    setPopularityLevelFilter('');
    setImportanceLevelFilter('');

    setCurrentPage(1);
  };

  // Determine Severity level of a node
  const getNodeSeverity = (node) => {
    const maxCvss = node.vulnerabilities?.reduce((max, v) => Math.max(max, Number(v.cvssScore || v.cvss || 0)), 0) || 0;
    if (maxCvss >= 9.0 || node.riskScore >= 80) return 'CRITICAL';
    if (maxCvss >= 7.0 || node.riskScore >= 60) return 'HIGH';
    if (maxCvss >= 4.0 || node.riskScore >= 40) return 'MEDIUM';
    if (maxCvss > 0) return 'LOW';
    return 'SAFE';
  };

  // Process & Filter graph data
  const filteredNodes = useMemo(() => {
    return graph.filter(node => {
      // Name Search
      if (search && !node.name.toLowerCase().includes(search.toLowerCase())) {
        return false;
      }
      // CVE Search
      if (cveSearch) {
        const hasCve = node.vulnerabilities?.some(v => v.cveId.toLowerCase().includes(cveSearch.toLowerCase()));
        if (!hasCve) return false;
      }
      // Severity Filter
      const sev = getNodeSeverity(node);
      if (severityFilter && sev !== severityFilter) {
        return false;
      }
      // Application Filter
      if (appFilter && !node.affectedApplications?.includes(appFilter)) {
        return false;
      }
      // Dependency Type
      if (depTypeFilter) {
        const isDirect = node.depth === 0;
        if (depTypeFilter === 'direct' && !isDirect) return false;
        if (depTypeFilter === 'transitive' && isDirect) return false;
      }
      // License Risk
      if (licenseRiskFilter && String(node.licenseRisk?.level).toUpperCase() !== licenseRiskFilter) {
        return false;
      }
      // Maintenance Status
      if (maintenanceFilter && String(node.maintenanceRisk?.level).toUpperCase() !== maintenanceFilter) {
        return false;
      }
      // Risk Score
      if (node.riskScore < minRiskScore) {
        return false;
      }

      // Checkbox Toggles
      if (onlyCritical && sev !== 'CRITICAL') return false;
      if (onlyVulnerable && (!node.vulnerabilities || node.vulnerabilities.length === 0)) return false;
      if (onlyTransitive && node.depth === 0) return false;
      if (onlyDirect && node.depth > 0) return false;
      if (onlyLicenseConflicts && node.licenseRisk?.level !== 'High' && node.licenseRisk?.level !== 'Critical') return false;
      if (onlyUnmaintained && node.maintenanceRisk?.level !== 'High') return false;

      // NEW ANOMALIES TOGGLES
      if (onlyConflicts && !node.hasVersionConflict) return false;
      if (onlyDiamonds && !node.hasDiamondDependency) return false;
      if (onlyHighExploitability && !node.vulnerabilities?.some(v => String(v.exploitability).toUpperCase() === 'HIGH')) return false;
      if (onlyPatchAvailable && node.remediationStatus !== 'PATCH_AVAILABLE') return false;
      if (onlyNoPatchAvailable && node.remediationStatus !== 'MITIGATION_REQUIRED') return false;
      if (onlyHighBlastRadius && node.impactLevel !== 'High' && node.impactLevel !== 'Very High') return false;

      // NEW FEATURES FILTERING
      if (onlyAging && node.maintenanceStatus !== 'Aging') return false;
      if (onlyStale && node.maintenanceStatus !== 'Stale') return false;
      if (onlyMultiplePaths && (!node.pathCount || node.pathCount <= 1)) return false;
      if (popularityLevelFilter && node.popularityLevel !== popularityLevelFilter) return false;
      if (importanceLevelFilter && node.importanceLevel !== importanceLevelFilter) return false;

      return true;
    });
  }, [graph, search, cveSearch, severityFilter, appFilter, depTypeFilter, licenseRiskFilter, maintenanceFilter, minRiskScore, onlyCritical, onlyVulnerable, onlyTransitive, onlyDirect, onlyLicenseConflicts, onlyUnmaintained, onlyConflicts, onlyDiamonds, onlyHighExploitability, onlyPatchAvailable, onlyNoPatchAvailable, onlyHighBlastRadius, onlyAging, onlyStale, onlyMultiplePaths, popularityLevelFilter, importanceLevelFilter]);

  // Sorting
  const sortedNodes = useMemo(() => {
    return [...filteredNodes].sort((a, b) => {
      let valA = a[sortKey];
      let valB = b[sortKey];

      if (sortKey === 'severity') {
        const rank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, SAFE: 1 };
        valA = rank[getNodeSeverity(a)];
        valB = rank[getNodeSeverity(b)];
      }

      if (sortKey === 'vulnerabilities') {
        valA = a.vulnerabilities?.length || 0;
        valB = b.vulnerabilities?.length || 0;
      }

      if (sortKey === 'affectedApplications') {
        valA = a.affectedApplications?.length || 0;
        valB = b.affectedApplications?.length || 0;
      }

      if (typeof valA === 'string') {
        return sortDirection === 'asc' 
          ? valA.localeCompare(valB) 
          : valB.localeCompare(valA);
      }

      return sortDirection === 'asc' 
        ? (valA || 0) - (valB || 0) 
        : (valB || 0) - (valA || 0);
    });
  }, [filteredNodes, sortKey, sortDirection]);

  // Pagination
  const paginatedNodes = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    return sortedNodes.slice(startIndex, startIndex + pageSize);
  }, [sortedNodes, currentPage, pageSize]);

  const totalPages = Math.ceil(sortedNodes.length / pageSize) || 1;

  // KPIs Calculations
  const kpis = useMemo(() => {
    const total = graph.length;
    const critical = graph.filter(node => getNodeSeverity(node) === 'CRITICAL').length;
    const high = graph.filter(node => getNodeSeverity(node) === 'HIGH').length;
    const apps = new Set();
    let totalRisk = 0;
    let directVulns = 0;
    let transitiveVulns = 0;

    graph.forEach(node => {
      totalRisk += node.riskScore || 0;
      const isVuln = node.vulnerabilities && node.vulnerabilities.length > 0;
      if (isVuln) {
        if (node.depth === 0) directVulns++;
        else transitiveVulns++;
        
        if (Array.isArray(node.affectedApplications)) {
          node.affectedApplications.forEach(a => apps.add(a));
        }
      }
    });

    return {
      total,
      critical,
      high,
      vulnerableApps: apps.size,
      avgRisk: total > 0 ? (totalRisk / total).toFixed(1) : 0,
      directVulns,
      transitiveVulns
    };
  }, [graph]);

  // Unique applications for filters
  const uniqueApplications = useMemo(() => {
    const apps = new Set();
    graph.forEach(node => {
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(a => apps.add(a));
      }
    });
    return Array.from(apps).sort();
  }, [graph]);

  // Visual Insights Charts Data
  const chartsData = useMemo(() => {
    // 1. Findings by severity
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
    graph.forEach(node => {
      counts[getNodeSeverity(node)]++;
    });
    const severityData = Object.entries(counts).map(([name, value]) => ({
      name,
      value,
      color: SEVERITY_COLORS[name]
    })).filter(x => x.value > 0);

    // 2. Findings by application
    const appCounts = {};
    graph.forEach(node => {
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(app => {
          appCounts[app] = (appCounts[app] || 0) + 1;
        });
      }
    });
    const appData = Object.entries(appCounts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    // 3. Risk score distribution
    const riskBuckets = Array.from({ length: 10 }, (_, i) => ({
      range: `${i * 10}-${(i + 1) * 10}`,
      count: 0
    }));
    graph.forEach(node => {
      const score = node.riskScore || 0;
      const index = Math.min(Math.floor(score / 10), 9);
      riskBuckets[index].count++;
    });

    // 4. Direct vs Transitive
    let directCount = 0;
    let transitiveCount = 0;
    graph.forEach(node => {
      if (node.vulnerabilities?.length > 0) {
        if (node.depth === 0) directCount++;
        else transitiveCount++;
      }
    });
    const directTransitiveData = [
      { name: 'Direct', value: directCount, color: '#3b82f6' },
      { name: 'Transitive', value: transitiveCount, color: '#8b5cf6' }
    ];

    return {
      severityData,
      appData,
      riskBuckets,
      directTransitiveData
    };
  }, [graph]);

  // Export handlers
  const handleExportCSV = () => {
    const headers = ['Severity', 'Package Name', 'Version', 'Risk Score', 'CVEs', 'Dependency Type', 'License', 'Last Updated', 'Priority'];
    const rows = filteredNodes.map(node => [
      getNodeSeverity(node),
      node.name,
      node.version,
      node.riskScore,
      node.vulnerabilities?.map(v => v.cveId).join('; ') || 'None',
      node.depth === 0 ? 'Direct' : 'Transitive',
      node.license || 'Unknown',
      node.lastUpdated || 'Unknown',
      node.priority
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.map(val => `"${val}"`).join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'dependlens-findings.csv');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredNodes, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', dataStr);
    link.setAttribute('download', 'dependlens-findings.json');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const toggleRow = (id) => {
    const newExpanded = new Set(expandedIds);
    if (newExpanded.has(id)) newExpanded.delete(id);
    else newExpanded.add(id);
    setExpandedIds(newExpanded);
  };

  const handleExpandAll = () => {
    setExpandedIds(new Set(paginatedNodes.map(n => n.id)));
  };

  const handleCollapseAll = () => {
    setExpandedIds(new Set());
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    alert(`Copied ${text} to clipboard!`);
  };

  const requestSort = (key) => {
    let direction = 'desc';
    if (sortKey === key && sortDirection === 'desc') {
      direction = 'asc';
    }
    setSortKey(key);
    setSortDirection(direction);
  };

  return (
    <div className="findings-page">
      <header className="findings-header">
        <h1>Security Findings</h1>
        <p>Prioritized vulnerabilities, license conflicts, and dependency risks across all applications.</p>
      </header>

      {/* KPI Insight Cards */}
      <section className="kpi-grid">
        <div className="kpi-card">
          <span className="kpi-card__label">Total Findings</span>
          <strong className="kpi-card__value">{kpis.total}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-card__label" style={{ color: '#ef4444' }}>Critical Findings</span>
          <strong className="kpi-card__value" style={{ color: '#ef4444' }}>{kpis.critical}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-card__label" style={{ color: '#f97316' }}>High Findings</span>
          <strong className="kpi-card__value" style={{ color: '#f97316' }}>{kpis.high}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-card__label">Vulnerable Apps</span>
          <strong className="kpi-card__value">{kpis.vulnerableApps}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-card__label">Avg Risk Score</span>
          <strong className="kpi-card__value" style={{ color: '#8b5cf6' }}>{kpis.avgRisk}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-card__label">Direct Vulns</span>
          <strong className="kpi-card__value">{kpis.directVulns}</strong>
        </div>
        <div className="kpi-card">
          <span className="kpi-card__label">Transitive Vulns</span>
          <strong className="kpi-card__value">{kpis.transitiveVulns}</strong>
        </div>
      </section>

      {/* Advanced Filter Bar */}
      <section className="findings-filters">
        <div className="findings-filters__header" onClick={() => setIsFiltersOpen(!isFiltersOpen)}>
          <h2>Advanced Findings Filter</h2>
          <span>{isFiltersOpen ? '▲' : '▼'}</span>
        </div>

        {isFiltersOpen && (
          <div className="findings-filters__content">
            <div className="findings-filters__row">
              <div className="filter-group">
                <label>Package Name</label>
                <input
                  type="text"
                  placeholder="e.g. lodash"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                />
              </div>

              <div className="filter-group">
                <label>CVE ID</label>
                <input
                  type="text"
                  placeholder="e.g. CVE-2023-..."
                  value={cveSearch}
                  onChange={e => setCveSearch(e.target.value)}
                />
              </div>

              <div className="filter-group">
                <label>Severity</label>
                <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
                  <option value="">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="SAFE">Safe</option>
                </select>
              </div>

              <div className="filter-group">
                <label>Application</label>
                <select value={appFilter} onChange={e => setAppFilter(e.target.value)}>
                  <option value="">All Applications</option>
                  {uniqueApplications.map(app => (
                    <option key={app} value={app}>{app}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="findings-filters__row">
              <div className="filter-group">
                <label>Dependency Type</label>
                <select value={depTypeFilter} onChange={e => setDepTypeFilter(e.target.value)}>
                  <option value="">All Types</option>
                  <option value="direct">Direct</option>
                  <option value="transitive">Transitive</option>
                </select>
              </div>

              <div className="filter-group">
                <label>Popularity Level</label>
                <select value={popularityLevelFilter} onChange={e => setPopularityLevelFilter(e.target.value)}>
                  <option value="">All Levels</option>
                  <option value="Very High">Very High</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Very Low">Very Low</option>
                </select>
              </div>

              <div className="filter-group">
                <label>Importance Level</label>
                <select value={importanceLevelFilter} onChange={e => setImportanceLevelFilter(e.target.value)}>
                  <option value="">All Levels</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="filter-group">
                <label>Min Risk Score ({minRiskScore})</label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={minRiskScore}
                  onChange={e => setMinRiskScore(Number(e.target.value))}
                />
              </div>
            </div>

            <div className="findings-filters__row">
              <div className="filter-checkbox-group">
                <label className="filter-checkbox">
                  <input type="checkbox" checked={onlyCritical} onChange={e => setOnlyCritical(e.target.checked)} />
                  Only Critical
                </label>
                <label className="filter-checkbox">
                  <input type="checkbox" checked={onlyVulnerable} onChange={e => setOnlyVulnerable(e.target.checked)} />
                  Only Vulnerable
                </label>
                <label className="filter-checkbox">
                  <input type="checkbox" checked={onlyTransitive} onChange={e => setOnlyTransitive(e.target.checked)} />
                  Only Transitive
                </label>
                <label className="filter-checkbox">
                  <input type="checkbox" checked={onlyDirect} onChange={e => setOnlyDirect(e.target.checked)} />
                  Only Direct
                </label>
                <label className="filter-checkbox">
                  <input type="checkbox" checked={onlyLicenseConflicts} onChange={e => setOnlyLicenseConflicts(e.target.checked)} />
                  License Conflicts
                </label>
                <label className="filter-checkbox">
                  <input type="checkbox" checked={onlyUnmaintained} onChange={e => setOnlyUnmaintained(e.target.checked)} />
                  Unmaintained
                </label>
              </div>
            </div>

            {/* NEW SUPPLY CHAIN ANOMALIES & HEALTH TOGGLES */}
            <div className="findings-filters__row" style={{ marginTop: '10px' }}>
              <div className="filter-checkbox-group">
                <label className="filter-checkbox" style={{ color: '#7c3aed' }}>
                  <input type="checkbox" checked={onlyConflicts} onChange={e => setOnlyConflicts(e.target.checked)} />
                  ⚠️ Version Conflicts
                </label>
                <label className="filter-checkbox" style={{ color: '#7c3aed' }}>
                  <input type="checkbox" checked={onlyDiamonds} onChange={e => setOnlyDiamonds(e.target.checked)} />
                  💎 Diamonds
                </label>
                <label className="filter-checkbox" style={{ color: '#fbbf24' }}>
                  <input type="checkbox" checked={onlyAging} onChange={e => setOnlyAging(e.target.checked)} />
                  🟡 Aging
                </label>
                <label className="filter-checkbox" style={{ color: '#f97316' }}>
                  <input type="checkbox" checked={onlyStale} onChange={e => setOnlyStale(e.target.checked)} />
                  🟠 Stale
                </label>
                <label className="filter-checkbox" style={{ color: '#8b5cf6' }}>
                  <input type="checkbox" checked={onlyMultiplePaths} onChange={e => setOnlyMultiplePaths(e.target.checked)} />
                  🔗 Multiple Paths
                </label>
                <label className="filter-checkbox" style={{ color: '#10b981' }}>
                  <input type="checkbox" checked={onlyPatchAvailable} onChange={e => setOnlyPatchAvailable(e.target.checked)} />
                  🟢 Patched
                </label>
                <label className="filter-checkbox" style={{ color: '#ef4444' }}>
                  <input type="checkbox" checked={onlyNoPatchAvailable} onChange={e => setOnlyNoPatchAvailable(e.target.checked)} />
                  🔴 Unpatched
                </label>
              </div>

              <button className="btn-reset" onClick={handleResetFilters}>
                Reset Filters
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Findings Table Component */}
      <section className="table-container">
        <div className="table-toolbar">
          <div className="table-toolbar__title">
            Vulnerability & Risk Findings ({filteredNodes.length})
          </div>
          <div className="table-toolbar__actions">
            <button className="btn-utility" onClick={handleExpandAll}>Expand All</button>
            <button className="btn-utility" onClick={handleCollapseAll}>Collapse All</button>
            <button className="btn-utility" onClick={handleExportCSV}>Export CSV</button>
            <button className="btn-utility" onClick={handleExportJSON}>Export JSON</button>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="findings-table">
            <thead>
              <tr>
                <th onClick={() => requestSort('severity')}>Severity</th>
                <th onClick={() => requestSort('name')}>Package</th>
                <th onClick={() => requestSort('version')}>Version</th>
                <th onClick={() => requestSort('riskScore')}>Risk Score</th>
                <th>Compounded Risk</th>
                <th>Maintenance</th>
                <th>Remediation</th>
                <th>Paths</th>
                <th>Popularity</th>
                <th>Importance</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="11" style={{ textAlign: 'center', padding: '40px' }}>Loading findings database...</td>
                </tr>
              ) : paginatedNodes.length > 0 ? (
                paginatedNodes.map(node => {
                  const isExpanded = expandedIds.has(node.id);
                  const severity = getNodeSeverity(node);

                  return (
                    <tr key={node.id} style={{ borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
                      <td>
                        <span className={`sev-badge sev-badge--${severity.toLowerCase()}`}>
                          {severity}
                        </span>
                      </td>
                      <td style={{ fontWeight: 'bold' }}>{node.name}</td>
                      <td className="mono">{node.version}</td>
                      <td className="mono">{node.riskScore}</td>
                      <td className="mono" style={{ fontWeight: 'bold', color: node.compoundedRisk >= 75 ? '#ef4444' : '#1e1b4b' }}>
                        {node.compoundedRisk || node.riskScore}
                      </td>
                      {/* Maintenance status badge */}
                      <td>
                        <span className="badge-count" style={{ background: MAINTENANCE_COLORS[node.maintenanceStatus || 'Healthy'], color: '#ffffff' }}>
                          {node.maintenanceStatus || 'Healthy'}
                        </span>
                      </td>
                      {/* Patch Status Column */}
                      <td>
                        {node.remediationStatus === 'PATCH_AVAILABLE' ? (
                          <span style={{ color: '#10b981', fontWeight: 'bold' }}>🟢 Patch</span>
                        ) : node.remediationStatus === 'MITIGATION_REQUIRED' ? (
                          <span style={{ color: '#ef4444', fontWeight: 'bold' }}>🔴 Mitigation</span>
                        ) : (
                          <span style={{ color: '#94a3b8' }}>N/A</span>
                        )}
                      </td>
                      {/* Path count */}
                      <td className="mono" style={{ fontWeight: 'bold' }}>
                        {node.pathCount || 1} paths
                      </td>
                      {/* Popularity */}
                      <td>
                        <span style={{ fontSize: '0.75rem', fontWeight: '700', color: '#3b82f6' }}>
                          📈 {node.popularityLevel || 'Low'}
                        </span>
                      </td>
                      {/* Importance Level */}
                      <td>
                        <span style={{
                          fontWeight: 'bold',
                          color: node.importanceLevel === 'Critical' || node.importanceLevel === 'High' ? '#ef4444' : '#10b981'
                        }}>
                          🛡️ {node.importanceLevel || 'Low'}
                        </span>
                      </td>
                      <td>
                        <button className="btn-utility" onClick={() => toggleRow(node.id)}>
                          {isExpanded ? 'Collapse' : 'Investigate'}
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="11" style={{ textAlign: 'center', padding: '40px' }}>No findings match the active filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="pagination">
          <button
            className="btn-nav"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
          >
            Previous
          </button>
          <span style={{ fontSize: '0.85rem', color: '#475569' }}>
            Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
          </span>
          <button
            className="btn-nav"
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
          >
            Next
          </button>
        </div>
      </section>

      {/* Expand Details Rows Overlay/Container */}
      {paginatedNodes.map(node => {
        if (!expandedIds.has(node.id)) return null;

        const isDirect = node.depth === 0;
        const vulnPatch = node.remediationStatus === 'PATCH_AVAILABLE' ? 'Upgrade Available' : 'No Patch / Mitigation Required';
        const parentChain = node.parents?.join(' → ') || 'Root direct dependency';
        const childrenList = node.children?.join(', ') || 'No sub-dependencies';

        return (
          <section key={`exp-${node.id}`} className="expanded-panel">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#7c3aed' }}>
                Vulnerability Detail & Blast Radius for <strong>{node.name}</strong>
              </h3>
              <button className="btn-utility" onClick={() => toggleRow(node.id)}>&times; Close Detail</button>
            </div>

            <div className="expanded-panel__grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
              {/* Security Narrative */}
              <div className="expanded-card">
                <h4>⚡ AI Security Narrative</h4>
                <p style={{ fontSize: '0.85rem', color: '#1e293b', lineHeight: 1.5 }}>
                  {node.securityNarrative}
                </p>
              </div>

              {/* Attack Path Analysis */}
              <div className="expanded-card">
                <h4>⛓️ AI Attack Path Analysis</h4>
                <p style={{ fontSize: '0.85rem', color: '#1e293b', lineHeight: 1.5, marginBottom: '8px' }}>
                  {node.attackAnalysis?.chainExplanation}
                </p>
                <div style={{ maxHeight: '100px', overflowY: 'auto', background: 'rgba(139,92,246,0.05)', padding: '6px', borderRadius: '6px' }}>
                  {node.dependencyPaths?.map((p, i) => (
                    <div key={i} className="mono" style={{ fontSize: '0.75rem', padding: '2px 0' }}>
                      {p.join(' → ')}
                    </div>
                  ))}
                </div>
              </div>

              {/* Risk Explainer */}
              <div className="expanded-card">
                <h4>📊 AI Risk Score Explainer</h4>
                <p style={{ fontSize: '0.85rem', color: '#1e293b', lineHeight: 1.5, marginBottom: '8px' }}>
                  {node.riskExplanation?.finalScoreExplanation}
                </p>
                <div className="details-grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', fontSize: '0.75rem' }}>
                  <div>Vuln contribution: <strong>+{node.riskExplanation?.vulnerabilityContribution || 0}</strong></div>
                  <div>Exploitability: <strong>+{node.riskExplanation?.exploitabilityContribution || 0}</strong></div>
                  <div>Maintenance: <strong>+{node.riskExplanation?.maintenanceContribution || 0}</strong></div>
                  <div>License: <strong>+{node.riskExplanation?.licenseContribution || 0}</strong></div>
                  <div>Paths offset: <strong>+{node.riskExplanation?.pathContribution || 0}</strong></div>
                  <div>Criticality multiplier: <strong>x{node.riskExplanation?.criticalityMultiplier || 1.0}</strong></div>
                </div>
              </div>

              {/* Business Impact */}
              <div className="expanded-card">
                <h4>🏢 AI Business Impact Engine</h4>
                <p style={{ fontSize: '0.85rem', color: '#1e293b', lineHeight: 1.5 }}>
                  {node.businessImpact?.impactNarrative}
                </p>
                <div className="details-grid" style={{ gridTemplateColumns: '1fr 1fr', marginTop: '8px', fontSize: '0.75rem' }}>
                  <div>Impact Level: <strong>{node.businessImpact?.impactLevel}</strong></div>
                  <div>Blast Score: <strong>{node.businessImpact?.blastRadius}</strong></div>
                </div>
              </div>

              {/* Remediation Advice */}
              <div className="expanded-card" style={{ gridColumn: 'span 2' }}>
                <h4>🛠️ AI Remediation Advice</h4>
                <div className="details-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                  <div className="details-item">
                    <label>Immediate Action</label>
                    <span style={{ fontWeight: 'bold', color: '#7c3aed' }}>{node.remediation?.immediateAction}</span>
                  </div>
                  <div className="details-item">
                    <label>Urgency Level</label>
                    <span style={{ fontWeight: 'bold', color: node.remediation?.urgency === 'Critical' ? '#ef4444' : '#fbbf24' }}>
                      {node.remediation?.urgency}
                    </span>
                  </div>
                </div>
                <p style={{ fontSize: '0.85rem', color: '#1e293b', lineHeight: 1.5, margin: '8px 0' }}>
                  {node.remediation?.remediationNarrative}
                </p>
                <div style={{ fontSize: '0.8rem', background: '#f8fafc', padding: '8px', borderRadius: '6px', border: '1px solid rgba(0,0,0,0.05)' }}>
                  <strong>Recommendation:</strong> {node.remediation?.recommendation}
                </div>
              </div>
            </div>
          </section>
        );
      })}

      {/* Visual charts analytics section */}
      <section className="charts-grid">
        {/* Findings by severity */}
        <div className="charts-card">
          <h3>Findings by Severity</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={chartsData.severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {chartsData.severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Legend formatter={(value) => <span style={{ color: '#475569', fontSize: '0.75rem' }}>{value}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Findings by application */}
        <div className="charts-card">
          <h3>Findings by Application</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={chartsData.appData}>
                <XAxis dataKey="name" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Issues count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk score distribution */}
        <div className="charts-card">
          <h3>Risk Score Distribution</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <AreaChart data={chartsData.riskBuckets}>
                <defs>
                  <linearGradient id="colorRiskFindings" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="range" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="count" stroke="#8b5cf6" strokeWidth={2} fillOpacity={1} fill="url(#colorRiskFindings)" name="Packages count" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Direct vs Transitive */}
        <div className="charts-card">
          <h3>Direct vs Transitive Vulnerabilities</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={chartsData.directTransitiveData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {chartsData.directTransitiveData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Legend formatter={(value) => <span style={{ color: '#475569', fontSize: '0.75rem' }}>{value}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>
    </div>
  );
}
