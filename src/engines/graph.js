function normalizeText(value) {
  return String(value ?? '').trim();
}

function toNodeId(name, version) {
  const normalizedName = normalizeText(name);
  const normalizedVersion = normalizeText(version);

  if (!normalizedName || !normalizedVersion) {
    return '';
  }

  return `${normalizedName}@${normalizedVersion}`;
}

function uniquePush(target, value) {
  if (!value || !normalizeText(value)) {
    return;
  }

  if (!target.includes(value)) {
    target.push(value);
  }
}

function getCriticalityMultiplier(criticality) {
  if (criticality === 'CRITICAL') {
    return 1.5;
  }

  if (criticality === 'HIGH') {
    return 1.3;
  }

  if (criticality === 'MEDIUM') {
    return 1.1;
  }

  return 1;
}

function getApplicationMetadata(applicationId, applicationsMap = new Map()) {
  const application = applicationsMap.get(applicationId);

  if (!application) {
    return null;
  }

  return {
    app_id: normalizeText(application.app_id || applicationId),
    name: normalizeText(application.name || applicationId),
    criticality: normalizeText(application.criticality || 'LOW').toUpperCase(),
    business_owner: normalizeText(application.business_owner),
    department: normalizeText(application.department),
    deployment: normalizeText(application.deployment),
    language: normalizeText(application.language),
    license_model: normalizeText(application.license_model || 'proprietary'),
  };
}

function enrichNodeWithApplication(node, applicationId, applicationsMap = new Map()) {
  if (!node || !applicationId) {
    return;
  }

  const application = getApplicationMetadata(applicationId, applicationsMap);

  if (!application) {
    return;
  }

  uniquePush(node.affectedApplications, application.name);

  const appDetail = {
    app_id: application.app_id,
    name: application.name,
    criticality: application.criticality || 'LOW',
    business_owner: application.business_owner,
    department: application.department,
    deployment: application.deployment,
    language: application.language,
    license_model: application.license_model || 'proprietary',
  };

  const alreadyAttached = node.applicationDetails.some((detail) => detail.app_id === appDetail.app_id);

  if (!alreadyAttached) {
    node.applicationDetails.push(appDetail);
  }

  uniquePush(node.businessCriticality, appDetail.criticality);
  uniquePush(node.deployment, appDetail.deployment);
  uniquePush(node.department, appDetail.department);
  uniquePush(node.owners, appDetail.business_owner);

  node.criticalityMultiplier = Math.max(
    Number(node.criticalityMultiplier) || 1,
    getCriticalityMultiplier(appDetail.criticality)
  );
}

function ensureNode(graph, name, version, fallback = {}) {
  const id = toNodeId(name, version);

  if (!id) {
    return null;
  }

  if (!graph.has(id)) {
    graph.set(id, {
      id,
      name: normalizeText(name),
      version: normalizeText(version),
      license: normalizeText(fallback.license),
      lastUpdated: normalizeText(fallback.lastUpdated),
      depth: Number(fallback.depth) || 0,
      parents: [],
      children: [],
      paths: [],
      affectedApplications: [],
      applicationDetails: [],
      businessCriticality: [],
      deployment: [],
      department: [],
      owners: [],
      vulnerabilities: [],
      criticalityMultiplier: 1,
    });
  }

  return graph.get(id);
}

function assignDepth(graph, nodeId, depth = 0, visited = new Set()) {
  const node = graph.get(nodeId);

  if (!node || visited.has(nodeId)) {
    return;
  }

  visited.add(nodeId);
  node.depth = Math.max(Number(node.depth) || 0, Number(depth) || 0);

  for (const childId of node.children) {
    assignDepth(graph, childId, Number(node.depth) + 1, visited);
  }
}

function buildGraph(dependencies, applicationsMap = new Map(), transitiveDependencies = []) {
  const graph = new Map();
  const rows = Array.isArray(dependencies) ? dependencies : [];
  const edges = Array.isArray(transitiveDependencies) ? transitiveDependencies : [];

  const resolvedVersionMap = new Map();
  for (const dep of rows) {
    const appId = normalizeText(dep.application_id || dep.app_id || '');
    const lib = normalizeText(dep.library || dep.package_name || dep.name || '');
    const version = normalizeText(dep.version || '');
    resolvedVersionMap.set(`${appId}::${lib}`, version);
  }

  for (const dependency of rows) {
    const name = normalizeText(dependency.library || dependency.package_name);
    const version = normalizeText(dependency.version);
    const node = ensureNode(graph, name, version, {
      license: dependency.license || '',
      lastUpdated: dependency.last_updated || dependency.lastUpdated || '',
      depth: Number(dependency.depth) || 0,
    });

    if (!node) {
      continue;
    }

    node.license = normalizeText(node.license || dependency.license);
    node.lastUpdated = normalizeText(node.lastUpdated || dependency.last_updated || dependency.lastUpdated);
    node.depth = Math.max(Number(node.depth) || 0, Number(dependency.depth) || 0);
    enrichNodeWithApplication(node, dependency.application_id, applicationsMap);
  }

  for (const edge of edges) {
    const appId = normalizeText(edge.application_id);
    const parentNode = ensureNode(graph, edge.parent_library, edge.parent_version, { depth: 0 });
    
    const childLibNormalized = normalizeText(edge.child_library);
    const resolvedChildVersion = resolvedVersionMap.get(`${appId}::${childLibNormalized}`) || edge.child_version;
    const childNode = ensureNode(graph, edge.child_library, resolvedChildVersion, { depth: 1 });

    if (!parentNode || !childNode) {
      continue;
    }

    enrichNodeWithApplication(parentNode, edge.application_id, applicationsMap);
    enrichNodeWithApplication(childNode, edge.application_id, applicationsMap);

    uniquePush(parentNode.children, childNode.id);
    uniquePush(childNode.parents, parentNode.id);
  }

  const dfs = (nodeId, currentPath, applicationName) => {
    const node = graph.get(nodeId);

    if (!node) {
      return;
    }

    uniquePush(node.affectedApplications, applicationName);

    const pathKey = JSON.stringify(currentPath);
    const pathExists = node.paths.some((path) => JSON.stringify(path) === pathKey);

    if (!pathExists) {
      node.paths.push([...currentPath]);
    }

    for (const childId of node.children) {
      if (!currentPath.includes(childId)) {
        dfs(childId, [...currentPath, childId], applicationName);
      }
    }
  };

  for (const dependency of rows) {
    const isDirect = String(dependency.dependency_type || '').toLowerCase() === 'direct';
    const rootName = normalizeText(dependency.library || dependency.package_name);
    const rootVersion = normalizeText(dependency.version);
    const rootId = toNodeId(rootName, rootVersion);
    const applicationId = normalizeText(dependency.application_id);
    const application = getApplicationMetadata(applicationId, applicationsMap);
    const applicationName = application?.name || applicationId || 'Unknown Application';

    if (!isDirect || !rootId) {
      continue;
    }

    dfs(rootId, [applicationName, rootId], applicationName);
  }

  for (const dependency of rows) {
    const isDirect = String(dependency.dependency_type || '').toLowerCase() === 'direct';

    if (!isDirect) {
      continue;
    }

    const rootId = toNodeId(normalizeText(dependency.library || dependency.package_name), normalizeText(dependency.version));

    if (rootId) {
      assignDepth(graph, rootId, 0, new Set());
    }
  }

  return graph;
}

module.exports = {
  buildGraph,
};
