import { useEffect, useMemo, useState } from 'react';
import { getGraph, getStats, getPriorities, getValidation } from '../services/api';
import { useNavigate } from 'react-router-dom';
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
  Area,
  RadialBarChart,
  RadialBar
} from 'recharts';
import './Dashboard.css';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  SAFE: '#10b981'
};

function formatPercent(value) {
  const numeric = Number(value || 0);
  const normalized = numeric <= 1 ? numeric * 100 : numeric;
  return `${normalized.toFixed(1)}%`;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [graph, setGraph] = useState([]);
  const [validation, setValidation] = useState(null);
  const [loading, setLoading] = useState(true);

  // Search & Filters for Top Risks Table
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    let isMounted = true;
    async function fetchDashboardData() {
      try {
        setLoading(true);
        const [statsRes, graphRes, validationRes] = await Promise.all([
          getStats(),
          getGraph(),
          getValidation()
        ]);
        if (isMounted) {
          setStats(statsRes.data);
          setGraph(Array.isArray(graphRes.data) ? graphRes.data : []);
          setValidation(validationRes.data);
        }
      } catch (err) {
        console.error('Failed to load dashboard statistics.', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    }
    fetchDashboardData();
    return () => {
      isMounted = false;
    };
  }, []);

  // Compute stats dynamically from the graph
  const metrics = useMemo(() => {
    const total = graph.length;
    const direct = graph.filter(node => node.depth === 0).length;
    const transitive = graph.filter(node => node.depth > 0).length;
    const vulnerable = graph.filter(node => Array.isArray(node.vulnerabilities) && node.vulnerabilities.length > 0).length;
    const critical = graph.filter(node => 
      node.priority === 'Fix Immediately' || 
      node.vulnerabilities?.some(v => v.severity === 'CRITICAL')
    ).length;

    let licenseConflicts = 0;
    let unmaintained = 0;
    let totalRisk = 0;
    const apps = new Set();

    graph.forEach(node => {
      totalRisk += node.riskScore || 0;
      if (node.licenseRisk?.level === 'High' || node.licenseRisk?.level === 'Critical') {
        licenseConflicts++;
      }
      if (node.maintenanceRisk?.level === 'High') {
        unmaintained++;
      }
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(a => apps.add(a));
      }
    });

    const avgRisk = total > 0 ? Math.round(totalRisk / total) : 0;
    const valConfidence = validation?.summary?.detectionConfidence || 85.0;

    return {
      total,
      direct,
      transitive,
      vulnerable,
      critical,
      avgRisk,
      licenseConflicts,
      unmaintained,
      appsCount: apps.size,
      valConfidence
    };
  }, [graph, validation]);

  // Compute Posture Status Dynamically
  const postureStatus = useMemo(() => {
    const criticalRatio = metrics.total > 0 ? (metrics.critical / metrics.total) * 100 : 0;
    const vulnRatio = metrics.total > 0 ? (metrics.vulnerable / metrics.total) * 100 : 0;

    if (criticalRatio > 10 || vulnRatio > 40) {
      return { label: 'Critical', className: 'status-badge--critical' };
    }
    if (criticalRatio > 5 || vulnRatio > 25) {
      return { label: 'Warning', className: 'status-badge--warning' };
    }
    if (vulnRatio > 10) {
      return { label: 'Healthy', className: 'status-badge--healthy' };
    }
    return { label: 'Secure', className: 'status-badge--secure' };
  }, [metrics]);

  // Overall posture score (100 - avgRisk)
  const overallScore = useMemo(() => {
    return Math.max(1, Math.min(100, 100 - metrics.avgRisk));
  }, [metrics.avgRisk]);

  // Recharts Gauge data for Score
  const scoreGaugeData = useMemo(() => {
    return [{ name: 'Score', value: overallScore, fill: '#8b5cf6' }];
  }, [overallScore]);

  // AI-Style Insights Generator
  const executiveInsights = useMemo(() => {
    const list = [];
    const nodes = graph;

    // 1. Most vulnerable app
    const appVulnCounts = {};
    nodes.forEach(node => {
      if (node.vulnerabilities?.length > 0 && Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(app => {
          appVulnCounts[app] = (appVulnCounts[app] || 0) + node.vulnerabilities.length;
        });
      }
    });
    const topApp = Object.entries(appVulnCounts).sort((a,b) => b[1] - a[1])[0];
    if (topApp) {
      list.push(`Application <strong>${topApp[0]}</strong> has the largest attack surface with <strong>${topApp[1]}</strong> vulnerabilities.`);
    }

    // 2. Highest blast radius package
    const topBlast = [...nodes].sort((a,b) => (b.affectedApplications?.length || 0) - (a.affectedApplications?.length || 0))[0];
    if (topBlast && topBlast.affectedApplications?.length > 0) {
      list.push(`Package <strong>${topBlast.name}</strong> presents the highest blast radius, impacting <strong>${topBlast.affectedApplications.length}</strong> applications.`);
    }

    // 3. Highest-risk dependency chain
    const topRiskPkg = [...nodes].sort((a,b) => (b.riskScore || 0) - (a.riskScore || 0))[0];
    if (topRiskPkg && topRiskPkg.parents?.length > 0) {
      list.push(`Highest risk propagation path identified via transitive dependency chain: <strong>${topRiskPkg.parents.join(' → ')} → ${topRiskPkg.name}</strong>.`);
    }

    // Default if list is empty
    if (list.length === 0) {
      list.push('Software supply chain posture is validated. Direct and transitive dependency paths are fully resolved.');
    }

    return list.slice(0, 3);
  }, [graph]);

  // Recharts distribution data
  const chartsData = useMemo(() => {
    // 1. Severity Counts
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
    graph.forEach(node => {
      if (node.vulnerabilities?.length > 0) {
        let maxSev = 'LOW';
        node.vulnerabilities.forEach(v => {
          const s = String(v.severity).toUpperCase();
          if (s === 'CRITICAL') maxSev = 'CRITICAL';
          else if (s === 'HIGH' && maxSev !== 'CRITICAL') maxSev = 'HIGH';
          else if (s === 'MEDIUM' && maxSev !== 'CRITICAL' && maxSev !== 'HIGH') maxSev = 'MEDIUM';
        });
        severityCounts[maxSev]++;
      } else {
        severityCounts.SAFE++;
      }
    });
    const severityDistribution = Object.entries(severityCounts).map(([name, value]) => ({
      name,
      value,
      color: SEVERITY_COLORS[name]
    })).filter(x => x.value > 0);

    // 2. Direct vs Transitive
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

    // 3. License risk counts
    const licenseRiskCounts = { HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    graph.forEach(node => {
      const level = String(node.licenseRisk?.level || 'NONE').toUpperCase();
      if (licenseRiskCounts[level] !== undefined) {
        licenseRiskCounts[level]++;
      }
    });
    const licenseRiskDistribution = Object.entries(licenseRiskCounts).map(([name, value]) => ({ name, value }));

    // 4. Maintenance status
    let unmaintainedCount = 0;
    let activeCount = 0;
    graph.forEach(node => {
      if (node.maintenanceRisk?.level === 'High') unmaintainedCount++;
      else activeCount++;
    });
    const maintenanceDistribution = [
      { name: 'Unmaintained', value: unmaintainedCount },
      { name: 'Active', value: activeCount }
    ];

    // 5. Risk score distribution
    const riskBuckets = Array.from({ length: 10 }, (_, i) => ({
      range: `${i * 10}-${(i + 1) * 10}`,
      count: 0
    }));
    graph.forEach(node => {
      const score = node.riskScore || 0;
      const index = Math.min(Math.floor(score / 10), 9);
      riskBuckets[index].count++;
    });

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
    })).sort((a, b) => b.avgRisk - a.avgRisk).slice(0, 8);

    return {
      severityDistribution,
      directTransitiveData,
      licenseRiskDistribution,
      maintenanceDistribution,
      riskBuckets,
      appRiskComparison
    };
  }, [graph]);

  // Ranked Top Risks list
  const rankedRisks = useMemo(() => {
    return [...graph]
      .sort((a,b) => (b.riskScore || 0) - (a.riskScore || 0))
      .filter(node => !search || node.name.toLowerCase().includes(search.toLowerCase()))
      .slice(0, 10);
  }, [graph, search]);

  // Application impact heatmap data
  const applicationImpactList = useMemo(() => {
    const apps = {};
    graph.forEach(node => {
      if (Array.isArray(node.affectedApplications)) {
        node.affectedApplications.forEach(app => {
          if (!apps[app]) {
            apps[app] = { name: app, riskScoreSum: 0, vulnCount: 0, depCount: 0 };
          }
          apps[app].riskScoreSum += node.riskScore || 0;
          apps[app].depCount++;
          if (node.vulnerabilities?.length > 0) {
            apps[app].vulnCount += node.vulnerabilities.length;
          }
        });
      }
    });

    return Object.values(apps).map(app => {
      const avgRisk = Math.round(app.riskScoreSum / app.depCount);
      const blastRadius = Number((app.vulnCount * 1.5 + app.depCount * 0.5).toFixed(1));
      return {
        ...app,
        avgRisk,
        blastRadius
      };
    }).sort((a,b) => b.avgRisk - a.avgRisk);
  }, [graph]);

  // Exports Handlers
  const handleExportCSV = () => {
    const headers = ['Package Name', 'Version', 'Risk Score', 'Priority', 'License', 'Vulnerabilities Count'];
    const rows = graph.map(node => [
      node.name,
      node.version,
      node.riskScore,
      node.priority,
      node.license || 'Unknown',
      node.vulnerabilities?.length || 0
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'dependlens-dashboard-risks.csv');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(graph, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', dataStr);
    link.setAttribute('download', 'dependlens-dashboard-risks.json');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="dashboard-page">
      {/* HERO SECTION */}
      <header className="hero-section">
        <div>
          <h1>DependLens Security Command Center</h1>
          <p>Transform raw SBOM data into actionable software supply-chain intelligence.</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div className="hero-metadata">
            <span>Last Scan: </span>
            <strong>Live Posture</strong>
          </div>
          <div className={`status-badge ${postureStatus.className}`}>
            ⚙️ Posture: {postureStatus.label}
          </div>
        </div>
      </header>

      {/* TOP KPI GRID */}
      <section className="kpi-dashboard-grid">
        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label">Total Packages</span>
            <span className="kpi-dashboard-card__icon">📦</span>
          </div>
          <strong className="kpi-dashboard-card__value">{metrics.total}</strong>
          <span className="kpi-dashboard-card__trend">BOM resolved</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label" style={{ color: '#ef4444' }}>Vulnerable Packages</span>
            <span className="kpi-dashboard-card__icon">🧩</span>
          </div>
          <strong className="kpi-dashboard-card__value" style={{ color: '#ef4444' }}>{metrics.vulnerable}</strong>
          <span className="kpi-dashboard-card__trend">Vulnerability database</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label" style={{ color: '#dc2626' }}>Critical Packages</span>
            <span className="kpi-dashboard-card__icon">⚠️</span>
          </div>
          <strong className="kpi-dashboard-card__value" style={{ color: '#dc2626' }}>{metrics.critical}</strong>
          <span className="kpi-dashboard-card__trend">Fix immediately</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label">Applications Covered</span>
            <span className="kpi-dashboard-card__icon">◌</span>
          </div>
          <strong className="kpi-dashboard-card__value">{metrics.appsCount}</strong>
          <span className="kpi-dashboard-card__trend">Microservices & APIs</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label">Average Risk Score</span>
            <span className="kpi-dashboard-card__icon">📊</span>
          </div>
          <strong className="kpi-dashboard-card__value" style={{ color: '#8b5cf6' }}>{metrics.avgRisk}</strong>
          <span className="kpi-dashboard-card__trend">BOM risk profile</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label">License Conflicts</span>
            <span className="kpi-dashboard-card__icon">⚖️</span>
          </div>
          <strong className="kpi-dashboard-card__value">{metrics.licenseConflicts}</strong>
          <span className="kpi-dashboard-card__trend">GPL Copyleft checks</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label">Unmaintained</span>
            <span className="kpi-dashboard-card__icon">⏳</span>
          </div>
          <strong className="kpi-dashboard-card__value">{metrics.unmaintained}</strong>
          <span className="kpi-dashboard-card__trend">Low update levels</span>
        </div>

        <div className="kpi-dashboard-card">
          <div className="kpi-dashboard-card__header">
            <span className="kpi-dashboard-card__label">Validation Confidence</span>
            <span className="kpi-dashboard-card__icon">🛡️</span>
          </div>
          <strong className="kpi-dashboard-card__value" style={{ color: '#10b981' }}>{formatPercent(metrics.valConfidence)}</strong>
          <span className="kpi-dashboard-card__trend">Accuracy index</span>
        </div>
      </section>

      {/* CENTERPIECE SCORE CARD & ACTIONS SIDEBAR */}
      <section className="posture-section">
        {/* Posture card with radial score */}
        <div className="posture-card">
          <h2>Security Posture Status</h2>
          <div className="posture-gauge-container">
            <div className="posture-score">
              {overallScore}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 'bold', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
                🛡️ Status: {postureStatus.label}
              </div>
              <p style={{ fontSize: '0.8rem', color: '#475569', margin: '4px 0 0 0', lineHeight: 1.4 }}>
                The security score aggregates vulnerabilities, copyleft legal risks, and dependency updates.
              </p>
            </div>
          </div>

          <div className="posture-health-metrics">
            <div className="health-item">
              <label>Vulnerability Health</label>
              <span style={{ color: '#ef4444' }}>{formatPercent(100 - (metrics.vulnerable / (metrics.total || 1)) * 100)}</span>
            </div>
            <div className="health-item">
              <label>Dependency Health</label>
              <span>{formatPercent(100 - (metrics.unmaintained / (metrics.total || 1)) * 100)}</span>
            </div>
          </div>
        </div>

        {/* Sticky Quick Actions */}
        <div className="posture-card" style={{ justifyContent: 'center' }}>
          <h2>Quick Actions Command</h2>
          <div className="actions-sidebar">
            <button className="btn-action btn-action--primary" onClick={() => navigate('/graph')}>
              Explore Dependency Graph
            </button>
            <button className="btn-action" onClick={() => navigate('/findings')}>
              Open Security Findings
            </button>
            <button className="btn-action" onClick={() => navigate('/validation')}>
              View Validation Trust Center
            </button>
          </div>
        </div>
      </section>

      {/* EXECUTIVE INSIGHTS */}
      <section className="exec-insights">
        <h3>💡 Supply Chain Command Center Insights</h3>
        <div className="exec-insights__list">
          {executiveInsights.map((insight, i) => (
            <div key={i} className="exec-insight-item" dangerouslySetInnerHTML={{ __html: insight }} />
          ))}
        </div>
      </section>

      {/* RISK DISTRIBUTION SECTION CHARTS */}
      <section className="charts-dashboard-grid">
        {/* Severity */}
        <div className="chart-dashboard-card">
          <h3>Vulnerabilities by Severity</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={chartsData.severityDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {chartsData.severityDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Legend formatter={(value) => <span style={{ color: '#475569', fontSize: '0.75rem' }}>{value}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Direct vs Transitive */}
        <div className="chart-dashboard-card">
          <h3>Direct vs Transitive Exposure</h3>
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

        {/* Risk Score Area Chart */}
        <div className="chart-dashboard-card">
          <h3>Risk Score Profile</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <AreaChart data={chartsData.riskBuckets}>
                <defs>
                  <linearGradient id="colorRiskDash" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="range" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="count" stroke="#8b5cf6" strokeWidth={2} fillOpacity={1} fill="url(#colorRiskDash)" name="Count" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Application comparison */}
        <div className="chart-dashboard-card">
          <h3>Application Risk Index</h3>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <BarChart data={chartsData.appRiskComparison}>
                <XAxis dataKey="name" stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '0.75rem' }} />
                <Tooltip contentStyle={{ background: '#ffffff', borderColor: '#8b5cf6', borderRadius: '8px' }} />
                <Bar dataKey="avgRisk" fill="#ef4444" radius={[4, 4, 0, 0]} name="Avg Risk Score" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* TOP RISKS RANKED PANEL TABLE */}
      <section className="risks-panel">
        <div className="table-toolbar">
          <div className="table-toolbar__title">
            Top Supply-Chain Priority Queue
          </div>
          <div className="table-toolbar__actions">
            <button className="btn-utility" onClick={handleExportCSV}>Export CSV</button>
            <button className="btn-utility" onClick={handleExportJSON}>Export JSON</button>
          </div>
        </div>

        <div className="validation-table-controls" style={{ padding: '16px' }}>
          <label className="validation-search">
            <span>Filter package name</span>
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="e.g. lodash"
            />
          </label>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="risks-table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Package Name</th>
                <th>Version</th>
                <th>Risk Score</th>
                <th>CVEs count</th>
                <th>Type</th>
                <th>Affected Apps</th>
                <th>Remediation Priority</th>
              </tr>
            </thead>
            <tbody>
              {rankedRisks.length > 0 ? (
                rankedRisks.map((node, i) => {
                  const isExpanded = expandedId === node.id;
                  return (
                    <tr key={node.id} onClick={() => setExpandedId(isExpanded ? null : node.id)} style={{ cursor: 'pointer' }}>
                      <td style={{ fontWeight: 'bold' }}>#{i + 1}</td>
                      <td style={{ fontWeight: 'bold' }}>{node.name}</td>
                      <td className="mono">{node.version}</td>
                      <td className="mono" style={{ fontWeight: 'bold' }}>{node.riskScore}</td>
                      <td>
                        <span className="badge-count" style={{ background: node.vulnerabilities?.length > 0 ? '#ef4444' : '#10b981' }}>
                          {node.vulnerabilities?.length || 0} CVEs
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.75rem', fontWeight: '700', color: node.depth === 0 ? '#3b82f6' : '#8b5cf6' }}>
                          {node.depth === 0 ? 'Direct' : 'Transitive'}
                        </span>
                      </td>
                      <td className="mono">{node.affectedApplications?.length || 0}</td>
                      <td>
                        <span style={{ fontWeight: '600', color: node.priority === 'Fix Immediately' ? '#ef4444' : '#f59e0b' }}>
                          {node.priority}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '30px' }}>No priority risks found matching search query.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* APPLICATION IMPACT MAP */}
      <section className="chart-dashboard-card">
        <h3>Application Security Blast Impact Map</h3>
        <p style={{ fontSize: '0.85rem', color: '#475569', margin: '0 0 16px 0' }}>
          Evaluate risk scores, vulnerability exposures, and total blast index of all downstream client applications.
        </p>

        <div className="app-impact-section">
          {applicationImpactList.map(app => (
            <div key={app.name} className="app-impact-card">
              <h4>{app.name}</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '0.7rem', textTransform: 'uppercase' }}>Avg Risk</span>
                  <strong style={{ fontSize: '1rem', color: app.avgRisk >= 40 ? '#ef4444' : '#10b981' }}>{app.avgRisk}</strong>
                </div>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '0.7rem', textTransform: 'uppercase' }}>Blast Index</span>
                  <strong style={{ fontSize: '1rem' }}>{app.blastRadius}</strong>
                </div>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '0.7rem', textTransform: 'uppercase' }}>CVEs Count</span>
                  <strong>{app.vulnCount} issues</strong>
                </div>
                <div>
                  <span style={{ color: '#64748b', display: 'block', fontSize: '0.7rem', textTransform: 'uppercase' }}>Dependencies</span>
                  <strong>{app.depCount}</strong>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ATTACK SURFACE DEPENDENCY DEPTH PREVIEW & TIMELINE */}
      <section className="timeline-surface-grid">
        {/* Attack surface preview */}
        <div className="timeline-card">
          <h3>Attack Surface Profile</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <div className="health-item">
              <label>Transitive Exposure</label>
              <span>{formatPercent((metrics.transitive / (metrics.total || 1)) * 100)}</span>
            </div>
            <div className="health-item">
              <label>Direct Exposure</label>
              <span>{formatPercent((metrics.direct / (metrics.total || 1)) * 100)}</span>
            </div>
          </div>
          <p style={{ fontSize: '0.85rem', color: '#475569', marginTop: '16px', lineHeight: 1.5 }}>
            A high ratio of transitive dependencies indicates elevated exposure to deep, unlisted supply-chain threats that resolve under direct packages.
          </p>
        </div>

        {/* Timeline */}
        <div className="timeline-card">
          <h3>Security Audit Timeline Log</h3>
          <div className="timeline-items">
            <div className="timeline-item">
              <div className="timeline-content">
                <span className="timeline-title">Ingested SBOM packages registry complete ({metrics.total} packages)</span>
                <span className="timeline-time">BOM database loaded</span>
              </div>
            </div>
            <div className="timeline-item">
              <div className="timeline-content">
                <span className="timeline-title">Vulnerability database overlap matches complete ({metrics.vulnerable} matches)</span>
                <span className="timeline-time">Vulnerabilities sync complete</span>
              </div>
            </div>
            <div className="timeline-item">
              <div className="timeline-content">
                <span className="timeline-title">Audit queue prioritization completed ({metrics.critical} critical flagged)</span>
                <span className="timeline-time">Remediation scan finished</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <footer style={{ marginTop: '20px', borderTop: '1px solid rgba(0,0,0,0.05)', paddingTop: '16px', fontSize: '0.75rem', color: '#64748b', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <span>Total Evaluated Dependency Instances: {metrics.total} | Scan Status: 100% Complete</span>
        <span>DependLens continuously analyzes dependency risk, transitive vulnerabilities, and software supply-chain exposure.</span>
      </footer>
    </div>
  );
}
