function hasCriticalVulnerability(node) {
  return Array.isArray(node?.vulnerabilities)
    && node.vulnerabilities.some((vulnerability) => String(vulnerability?.severity || '').toUpperCase() === 'CRITICAL');
}

function hasHighVulnerability(node) {
  return Array.isArray(node?.vulnerabilities)
    && node.vulnerabilities.some((vulnerability) => String(vulnerability?.severity || '').toUpperCase() === 'HIGH');
}

function maxCvss(node) {
  const items = Array.isArray(node?.vulnerabilities) ? node.vulnerabilities : [];

  if (items.length === 0) {
    return 0;
  }

  return Math.max(...items.map((vulnerability) => Number(vulnerability?.cvssScore || vulnerability?.cvss || vulnerability?.cvss_score || 0)));
}

function prioritizeRisks(graph) {
  for (const node of graph.values()) {
    const hasVulnerability = Array.isArray(node.vulnerabilities) && node.vulnerabilities.length > 0;
    const isExplicitlyCritical = Boolean(node.isExplicitlyCritical);
    const criticalVulnerability = hasCriticalVulnerability(node);
    const highVulnerability = hasHighVulnerability(node);
    const highestCvss = maxCvss(node);

    if (node.riskScore >= 80 || criticalVulnerability || highestCvss >= 9.0) {
      node.priority = 'Fix Immediately';
    } else if (node.riskScore >= 55 || highVulnerability) {
      node.priority = 'Fix This Sprint';
    } else {
      node.priority = 'Monitor';
    }
  }

  return graph;
}

module.exports = {
  hasCriticalVulnerability,
  hasHighVulnerability,
  maxCvss,
  prioritizeRisks,
};
