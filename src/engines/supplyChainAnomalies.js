// Supply Chain Anomalies Analyzer Engine for DependLens

function analyzeSupplyChainAnomalies(graph) {
  // --- Helper: Path Resolution with Caching ---
  const pathCache = new Map();
  const getPaths = (nodeId) => {
    if (pathCache.has(nodeId)) return pathCache.get(nodeId);
    const node = graph.get(nodeId);
    if (!node) return [];
    if (node.depth === 0) {
      const res = (node.affectedApplications || []).map(app => [app, nodeId]);
      pathCache.set(nodeId, res);
      return res;
    }
    const res = [];
    for (const parentId of (node.parents || [])) {
      const parentPaths = getPaths(parentId);
      for (const p of parentPaths) {
        res.push([...p, nodeId]);
      }
    }
    pathCache.set(nodeId, res);
    return res;
  };

  // --- Helper: Count Transitive Descendants ---
  const countTransitiveDescendants = (nodeId, visited = new Set()) => {
    const node = graph.get(nodeId);
    if (!node || visited.has(nodeId)) return 0;
    visited.add(nodeId);

    let count = 0;
    const children = node.children || [];
    for (const childId of children) {
      count++;
      count += countTransitiveDescendants(childId, visited);
    }
    return count;
  };

  // --- 1. Version Conflict Detection ---
  const appPackageVersions = new Map(); // appId -> Map(packageName -> Set(version))

  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    const pkgName = node.name;
    const version = node.version;
    const apps = node.affectedApplications || [];

    for (const app of apps) {
      if (!appPackageVersions.has(app)) {
        appPackageVersions.set(app, new Map());
      }
      const pkgMap = appPackageVersions.get(app);
      if (!pkgMap.has(pkgName)) {
        pkgMap.set(pkgName, new Set());
      }
      pkgMap.get(pkgName).add(version);
    }
  }

  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    const pkgName = node.name;
    const version = node.version;
    const conflictApps = [];
    const conflictingVersionsSet = new Set();

    const apps = node.affectedApplications || [];
    for (const app of apps) {
      const versionsInApp = appPackageVersions.get(app)?.get(pkgName) || new Set();
      if (versionsInApp.size > 1) {
        conflictApps.push(app);
        for (const v of versionsInApp) {
          if (v !== version) {
            conflictingVersionsSet.add(v);
          }
        }
      }
    }

    node.hasVersionConflict = conflictApps.length > 0;
    node.conflictingVersions = Array.from(conflictingVersionsSet);
    node.conflictApplications = conflictApps;
  }

  // --- 2. Diamond Dependency Detection ---
  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    const allPaths = getPaths(node.id);

    const appPaths = new Map();
    for (const path of allPaths) {
      const app = path[0];
      if (!appPaths.has(app)) {
        appPaths.set(app, []);
      }
      appPaths.get(app).push(path);
    }

    const diamondPaths = [];
    let hasDiamond = false;
    for (const [app, paths] of appPaths.entries()) {
      if (paths.length > 1) {
        hasDiamond = true;
        diamondPaths.push(...paths);
      }
    }

    node.hasDiamondDependency = hasDiamond;
    node.diamondPaths = diamondPaths;
  }

  // --- 3. Patch Feasibility Analysis (Node Remediation status mapping) ---
  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    const vulnerabilities = Array.isArray(node.vulnerabilities) ? node.vulnerabilities : [];
    
    let hasPatch = false;
    let recommendedVersion = null;

    for (const vuln of vulnerabilities) {
      const patchAvailable = vuln.patch_available || vuln.patchAvailable || (vuln.fixed_version || vuln.fixedVersion);
      if (patchAvailable) {
        hasPatch = true;
        recommendedVersion = vuln.fixed_version || vuln.fixedVersion || recommendedVersion;
        vuln.remediationType = "PATCH_AVAILABLE";
        vuln.recommendation = `Upgrade to v${vuln.fixed_version || vuln.fixedVersion}`;
      } else {
        vuln.remediationType = "MITIGATION_REQUIRED";
        vuln.recommendation = "No official patch available. Mitigation required.";
      }
    }

    // Set remediation type on node level
    node.remediationStatus = vulnerabilities.length > 0
      ? (hasPatch ? 'PATCH_AVAILABLE' : 'MITIGATION_REQUIRED')
      : 'NONE';
    node.recommendedVersion = recommendedVersion;
  }

  // --- 4. Blast Radius, Multiple-Path Risk, Popularity, and Importance scoring ---
  const blastScores = [];
  const popularityScores = [];
  const importanceScores = [];

  for (const node of graph.values()) {
    if (node.type === 'application') continue;

    const appsCount = node.affectedApplications?.length || 0;
    const paths = getPaths(node.id);
    const pathsCount = paths.length;
    const vulnDescendantsCount = Array.from(graph.values()).filter(d => 
      d.id !== node.id && 
      d.vulnerabilities?.length > 0 && 
      d.parents?.includes(node.id)
    ).length;

    // A. Blast Radius
    const blastScore = (appsCount * 4) + (pathsCount * 2) + (vulnDescendantsCount * 5);
    node.blastRadius = blastScore;
    blastScores.push(blastScore);

    // B. Multiple-Path Risk Weighting
    node.dependencyPaths = paths;
    node.pathCount = pathsCount;
    node.pathRiskMultiplier = Number((1 + (pathsCount - 1) * 0.1).toFixed(2));
    node.compoundedRisk = Number(Math.min(100, node.riskScore * node.pathRiskMultiplier).toFixed(2));

    // C. Popularity Score
    const parentsCount = node.parents?.length || 0;
    const childrenCount = node.children?.length || 0;
    const popScore = (appsCount * 10) + (parentsCount * 5) + (childrenCount * 2) + (pathsCount * 3);
    node.popularityScore = popScore;
    popularityScores.push(popScore);

    // D. Dependency Importance Score
    const descendantsCount = countTransitiveDescendants(node.id);
    const vulnsCount = node.vulnerabilities?.length || 0;
    const depth = node.depth || 0;
    const impScore = blastScore + Math.max(0, 10 - depth) * 5 + appsCount * 10 + descendantsCount * 3 + vulnsCount * 8;
    node.importanceScore = impScore;
    importanceScores.push(impScore);
  }

  // Define dynamic thresholds based on maximum values
  const maxBlast = Math.max(...blastScores, 1);
  const maxPopularity = Math.max(...popularityScores, 1);
  const maxImportance = Math.max(...importanceScores, 1);

  for (const node of graph.values()) {
    if (node.type === 'application') continue;

    // Blast Radius Levels
    const bScore = node.blastRadius || 0;
    if (bScore >= maxBlast * 0.75) node.impactLevel = 'Very High';
    else if (bScore >= maxBlast * 0.50) node.impactLevel = 'High';
    else if (bScore >= maxBlast * 0.25) node.impactLevel = 'Medium';
    else node.impactLevel = 'Low';

    // Popularity Levels
    const pScore = node.popularityScore || 0;
    if (pScore >= maxPopularity * 0.8) node.popularityLevel = 'Very High';
    else if (pScore >= maxPopularity * 0.6) node.popularityLevel = 'High';
    else if (pScore >= maxPopularity * 0.4) node.popularityLevel = 'Medium';
    else if (pScore >= maxPopularity * 0.2) node.popularityLevel = 'Low';
    else node.popularityLevel = 'Very Low';

    // Importance Levels
    const iScore = node.importanceScore || 0;
    if (iScore >= maxImportance * 0.75) node.importanceLevel = 'Critical';
    else if (iScore >= maxImportance * 0.50) node.importanceLevel = 'High';
    else if (iScore >= maxImportance * 0.25) node.importanceLevel = 'Medium';
    else node.importanceLevel = 'Low';
  }

  return graph;
}

module.exports = {
  analyzeSupplyChainAnomalies
};
