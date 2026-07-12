import { useEffect, useMemo, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import './DependencyGraph.css';

const riskBandColors = {
  safe: '#10b981', // green
  low: '#3b82f6',  // blue
  medium: '#fbbf24', // yellow
  high: '#f97316',  // orange
  critical: '#ef4444', // red
  vulnerable: '#ef4444',
  unmaintained: '#64748b' // gray
};

function normalizePriority(priority) {
  if (priority === 'Fix Immediately' || priority === 'Fix This Sprint' || priority === 'Monitor') {
    return priority;
  }
  return 'Monitor';
}

function getNodeTone(node) {
  const hasVulnerabilities = Array.isArray(node?.vulnerabilities) && node.vulnerabilities.length > 0;
  const licenseRisk = String(node?.licenseRisk?.level ?? '').toLowerCase();

  if (hasVulnerabilities) {
    return 'vulnerable';
  }
  if (licenseRisk === 'high' || licenseRisk === 'critical') {
    return 'high';
  }
  if (node?.maintenanceRisk?.level === 'High') {
    return 'unmaintained';
  }

  const score = Number(node?.riskScore ?? 0);
  if (score >= 70) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 25) return 'low';
  return 'safe';
}

function buildGraphData(payload = []) {
  if (!Array.isArray(payload) || payload.length === 0) {
    return { nodes: [], links: [] };
  }

  const packageNodes = payload.map((node, index) => {
    const depth = Number(node?.depth ?? 0);
    const depthNodes = payload.filter((candidate) => Number(candidate?.depth ?? 0) === depth);
    const laneIndex = depthNodes.findIndex((candidate) => candidate?.id === node?.id);
    const x = 160 + ((laneIndex % 5) * 180);
    const y = 120 + (depth * 150);

    return {
      id: node?.id,
      name: node?.name ?? node?.id,
      version: node?.version ?? '—',
      priority: normalizePriority(node?.priority),
      riskScore: Number(node?.riskScore ?? 0),
      depth,
      parents: Array.isArray(node?.parents) ? node.parents : [],
      children: Array.isArray(node?.children) ? node.children : [],
      vulnerabilities: Array.isArray(node?.vulnerabilities) ? node.vulnerabilities : [],
      licenseRisk: node?.licenseRisk ?? { level: 'Unknown', message: 'No data available' },
      maintenanceRisk: node?.maintenanceRisk ?? { level: 'Unknown', message: 'No data available' },
      affectedApplications: Array.isArray(node?.affectedApplications) ? node.affectedApplications : [],
      paths: Array.isArray(node?.paths) ? node.paths : [],
      type: 'package',
      fx: x,
      fy: y,
      index,
    };
  });

  const applicationIds = Array.from(
    new Set(
      payload.flatMap((node) => (Array.isArray(node?.affectedApplications) ? node.affectedApplications : []))
    )
  );

  const applicationNodes = applicationIds.map((applicationId, index) => ({
    id: applicationId,
    name: applicationId,
    version: 'application',
    priority: 'Application',
    riskScore: 0,
    depth: -1,
    parents: [],
    children: [],
    vulnerabilities: [],
    licenseRisk: { level: 'None', message: 'Application layer' },
    maintenanceRisk: { level: 'None', message: 'Application layer' },
    affectedApplications: [],
    paths: [],
    type: 'application',
    fx: 120 + (index % 5) * 190,
    fy: 40 + Math.floor(index / 5) * 70,
  }));

  const nodes = [...applicationNodes, ...packageNodes];

  const links = [
    ...packageNodes.flatMap((node) =>
      (node.parents || []).map((parentId) => ({
        source: parentId,
        target: node.id,
        kind: 'dependency',
      }))
    ),
    ...packageNodes.flatMap((node) =>
      (node.affectedApplications || []).map((applicationId) => ({
        source: applicationId,
        target: node.id,
        kind: 'application',
      }))
    ),
  ];

  return { nodes, links };
}

export default function DependencyGraph({ graph = [], filters = {}, graphMode = 'full', onSelectNode }) {
  const graphRef = useRef(null);
  const canvasRef = useRef(null);
  const [graphData, setGraphData] = useState(() => buildGraphData(graph));
  const [hoveredNode, setHoveredNode] = useState(null);
  const [canvasSize, setCanvasSize] = useState({ width: 980, height: 600 });
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    if (Array.isArray(graph) && graph.length > 0) {
      setGraphData(buildGraphData(graph));
    }
  }, [graph]);

  useEffect(() => {
    if (!canvasRef.current) return;
    const updateSize = () => {
      setCanvasSize({
        width: canvasRef.current.clientWidth,
        height: isFullscreen ? window.innerHeight - 80 : 600,
      });
    };
    updateSize();
    window.addEventListener('resize', updateSize);
    return () => window.removeEventListener('resize', updateSize);
  }, [isFullscreen]);

  useEffect(() => {
    if (graphRef.current && graphData.nodes.length > 0) {
      requestAnimationFrame(() => {
        graphRef.current.zoomToFit(500, 80);
      });
    }
  }, [graphData]);

  // Apply filters to nodes and links
  const { filteredNodes, filteredLinks } = useMemo(() => {
    const nodes = graphData.nodes.filter(node => {
      if (node.type === 'application') return true;

      // 1. Name search
      if (filters.search && !node.name.toLowerCase().includes(filters.search.toLowerCase())) {
        return false;
      }
      // 2. CVE ID search
      if (filters.cveSearch) {
        const hasCve = node.vulnerabilities?.some(v => v.cveId.toLowerCase().includes(filters.cveSearch.toLowerCase()));
        if (!hasCve) return false;
      }
      // 3. Application filter
      if (filters.appFilter && !node.affectedApplications?.includes(filters.appFilter)) {
        return false;
      }
      // 4. Version search
      if (filters.versionSearch && !node.version.toLowerCase().includes(filters.versionSearch.toLowerCase())) {
        return false;
      }
      // 5. Severity filter
      if (filters.severityFilter) {
        const hasSev = node.vulnerabilities?.some(v => String(v.severity).toUpperCase() === filters.severityFilter.toUpperCase());
        if (!hasSev) return false;
      }
      // 6. Risk score range
      if (node.riskScore < (filters.minRiskScore || 0)) {
        return false;
      }
      // 7. Depth filter
      if (filters.depthFilter !== '' && node.depth !== Number(filters.depthFilter)) {
        return false;
      }
      // 8. License filter
      if (filters.licenseTypeFilter && node.license !== filters.licenseTypeFilter) {
        return false;
      }
      // 9. Maintenance filter
      if (filters.maintenanceFilter) {
        if (filters.maintenanceFilter === 'High' && node.maintenanceRisk?.level !== 'High') return false;
        if (filters.maintenanceFilter === 'Low' && node.maintenanceRisk?.level === 'High') return false;
      }

      // Checkboxes
      if (filters.showOnlyVulnerable && (!node.vulnerabilities || node.vulnerabilities.length === 0)) {
        return false;
      }
      if (filters.showOnlyTransitive && node.depth === 0) {
        return false;
      }
      if (filters.showOnlyDirect && node.depth > 0) {
        return false;
      }
      if (filters.showOnlyLicenseConflicts && node.licenseRisk?.level !== 'High' && node.licenseRisk?.level !== 'Critical') {
        return false;
      }

      return true;
    });

    const nodeIds = new Set(nodes.map(n => n.id));
    const links = graphData.links.filter(link => {
      const srcId = typeof link.source === 'object' ? link.source.id : link.source;
      const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
      return nodeIds.has(srcId) && nodeIds.has(tgtId);
    });

    return { filteredNodes: nodes, filteredLinks: links };
  }, [graphData, filters]);

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ nodes: filteredNodes, links: filteredLinks }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", "dependlens-graph.json");
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="dependency-graph" style={{ position: 'relative' }}>
      <div className="dependency-graph__canvas" ref={canvasRef} style={{ height: isFullscreen ? 'calc(100vh - 40px)' : '600px' }}>
        <div className="dependency-graph__canvas-surface" style={{ height: '100%' }}>
          
          {/* Controls Overlay */}
          <div className="dependency-graph__controls" style={{ zIndex: 10 }}>
            <button className="dependency-graph__control-button" onClick={() => graphRef.current?.zoomToFit(400, 60)}>
              Fit to Screen
            </button>
            <button className="dependency-graph__control-button" onClick={() => setIsFullscreen(!isFullscreen)}>
              {isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
            </button>
            <button className="dependency-graph__control-button" onClick={handleExportJSON}>
              Export JSON
            </button>
          </div>

          <ForceGraph2D
            ref={graphRef}
            graphData={{ nodes: filteredNodes, links: filteredLinks }}
            width={canvasSize.width}
            height={canvasSize.height}
            nodeId="id"
            nodeLabel={(node) => `${node.name} @ v${node.version}`}
            nodeVal={(node) => {
              if (node.type === 'application') return 14;
              // Node size depends on affected apps, children, and riskScore
              const appCount = node.affectedApplications?.length || 1;
              const depCount = node.children?.length || 0;
              return Math.max(6, Math.min(22, 6 + (appCount * 2) + (depCount * 0.5) + (node.riskScore / 10)));
            }}
            linkDirectionalArrowLength={6}
            linkDirectionalArrowColor={() => 'rgba(139, 92, 246, 0.4)'}
            cooldownTicks={120}
            enableNodeDrag
            enableZoomInteraction
            enablePanInteraction
            onNodeHover={(node) => setHoveredNode(node)}
            onNodeClick={(node) => {
              if (node.type !== 'application' && onSelectNode) {
                onSelectNode(node);
              }
            }}
            linkCanvasObject={(link, ctx) => {
              const source = typeof link.source === 'object' ? link.source : null;
              const target = typeof link.target === 'object' ? link.target : null;
              if (!source || !target) return;

              ctx.save();
              
              // Edge styling based on Graph Mode
              let strokeColor = 'rgba(113, 130, 164, 0.2)';
              let strokeWidth = 0.8;
              let isGlow = false;

              if (graphMode === 'vulnerability') {
                const isVulnProp = (target.vulnerabilities?.length > 0);
                if (isVulnProp) {
                  strokeColor = 'rgba(239, 68, 68, 0.6)';
                  strokeWidth = 1.6;
                  isGlow = true;
                }
              } else if (graphMode === 'license') {
                const hasLicenseRisk = (target.licenseRisk?.level === 'High' || target.licenseRisk?.level === 'Critical');
                if (hasLicenseRisk) {
                  strokeColor = 'rgba(139, 92, 246, 0.6)';
                  strokeWidth = 1.6;
                  isGlow = true;
                }
              }

              if (hoveredNode && (source.id === hoveredNode.id || target.id === hoveredNode.id)) {
                strokeColor = 'rgba(139, 92, 246, 0.9)';
                strokeWidth = 2.0;
                isGlow = true;
              }

              if (isGlow) {
                ctx.shadowColor = strokeColor;
                ctx.shadowBlur = 8;
              }

              ctx.strokeStyle = strokeColor;
              ctx.lineWidth = strokeWidth;
              ctx.beginPath();
              ctx.moveTo(source.x, source.y);
              ctx.lineTo(target.x, target.y);
              ctx.stroke();
              ctx.restore();
            }}
            nodeCanvasObject={(node, ctx, globalScale) => {
              ctx.save();

              if (node.type === 'application') {
                const width = Math.max(100, ctx.measureText(node.name).width + 20);
                const height = 24;
                ctx.beginPath();
                ctx.roundRect(node.x - (width / 2), node.y - (height / 2), width, height, 6);
                ctx.fillStyle = 'rgba(15, 23, 42, 0.95)';
                ctx.strokeStyle = 'rgba(139, 92, 246, 0.6)';
                ctx.lineWidth = 1.2;
                ctx.fill();
                ctx.stroke();

                ctx.font = `bold 10px Inter, sans-serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = '#c084fc';
                ctx.fillText(node.name, node.x, node.y);
                ctx.restore();
                return;
              }

              // Compute Node styling based on Graph Mode
              let tone = getNodeTone(node);
              let color = riskBandColors[tone] || '#10b981';
              const appCount = node.affectedApplications?.length || 1;
              const depCount = node.children?.length || 0;
              const radius = Math.max(6, Math.min(22, 6 + (appCount * 2) + (depCount * 0.5) + (node.riskScore / 10)));

              if (graphMode === 'vulnerability') {
                const isVuln = node.vulnerabilities?.length > 0;
                color = isVuln ? '#ef4444' : '#10b981';
              } else if (graphMode === 'license') {
                const hasLic = node.licenseRisk?.level === 'High' || node.licenseRisk?.level === 'Critical';
                color = hasLic ? '#8b5cf6' : '#10b981';
              } else if (graphMode === 'heat') {
                // Risk score heat gradient (green -> yellow -> red)
                const score = node.riskScore || 0;
                if (score >= 70) color = '#ef4444';
                else if (score >= 40) color = '#fbbf24';
                else color = '#10b981';
              } else if (graphMode === 'business') {
                const criticality = String(node.businessCriticality?.[0] || '').toUpperCase();
                if (criticality === 'CRITICAL' || criticality === 'HIGH') color = '#ef4444';
                else if (criticality === 'MEDIUM') color = '#fbbf24';
                else color = '#10b981';
              }

              // Draw Main Node Circle
              ctx.beginPath();
              ctx.arc(node.x, node.y, radius, 0, Math.PI * 2, false);
              ctx.fillStyle = color;
              ctx.shadowColor = color;
              ctx.shadowBlur = node.vulnerabilities?.length > 0 ? 10 : 0;
              ctx.fill();
              ctx.shadowBlur = 0;

              // Draw Outlines / Borders
              ctx.beginPath();
              ctx.arc(node.x, node.y, radius + 1.5, 0, Math.PI * 2, false);
              if (node.licenseRisk?.level === 'High' || node.licenseRisk?.level === 'Critical') {
                ctx.strokeStyle = '#a78bfa'; // Purple outline for license conflict
                ctx.lineWidth = 1.5;
              } else if (node.maintenanceRisk?.level === 'High') {
                ctx.strokeStyle = '#94a3b8'; // Gray outline for unmaintained
                ctx.setLineDash([2, 2]);
                ctx.lineWidth = 1.2;
              } else {
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
                ctx.lineWidth = 1;
              }
              ctx.stroke();
              ctx.setLineDash([]); // Reset line dash

              // Draw CVE badge count (if any)
              if (node.vulnerabilities?.length > 0) {
                const badgeRadius = 6;
                const bx = node.x + radius - 2;
                const by = node.y - radius + 2;
                ctx.beginPath();
                ctx.arc(bx, by, badgeRadius, 0, Math.PI * 2, false);
                ctx.fillStyle = '#ef4444';
                ctx.fill();
                ctx.beginPath();
                ctx.arc(bx, by, badgeRadius, 0, Math.PI * 2, false);
                ctx.strokeStyle = '#ffffff';
                ctx.lineWidth = 1;
                ctx.stroke();

                ctx.font = 'bold 7px Inter, sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = '#ffffff';
                ctx.fillText(node.vulnerabilities.length, bx, by);
              }

              // Draw Warning Icons or Badges
              if (node.licenseRisk?.level === 'High' || node.licenseRisk?.level === 'Critical') {
                // Draw small yellow triangle warn icon
                const wx = node.x - radius + 2;
                const wy = node.y + radius - 2;
                ctx.beginPath();
                ctx.arc(wx, wy, 4, 0, Math.PI * 2, false);
                ctx.fillStyle = '#fbbf24';
                ctx.fill();
              }

              // Draw Text labels if zoomed in
              if (globalScale > 1.2) {
                ctx.font = `${10 / globalScale}px JetBrains Mono, monospace`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.fillStyle = '#cbd5e1';
                ctx.fillText(node.name, node.x, node.y + radius + 6);
              }

              ctx.restore();
            }}
          />
        </div>
      </div>
    </div>
  );
}
