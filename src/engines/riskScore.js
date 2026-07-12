const SEVERITY_WEIGHTS = {
  CRITICAL: 80,
  HIGH: 55,
  MEDIUM: 30,
  LOW: 15,
};

function contributionFromLicenseLevel(level) {
  const normalized = String(level || '').toUpperCase();

  if (normalized === 'CRITICAL' || normalized === 'UNKNOWN LICENSE RISK') {
    return 15;
  }

  if (normalized === 'HIGH') {
    return 10;
  }

  if (normalized === 'MEDIUM') {
    return 5;
  }

  return 0;
}

function contributionFromMaintenanceLevel(level) {
  const normalized = String(level || '').toUpperCase();

  if (normalized === 'HIGH' || normalized.includes('UNMAINTAINED')) {
    return 10;
  }

  return 0;
}

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

function getVulnerabilityContribution(vulnerabilities) {
  const items = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  if (items.length === 0) {
    return 0;
  }

  const weights = items.map((vulnerability) => {
    const severity = String(vulnerability?.severity || '').toUpperCase();
    return SEVERITY_WEIGHTS[severity] || 0;
  });

  const highestSeverityWeight = Math.max(...weights);
  const additionalWeight = Math.max(0, items.length - 1) * 5;

  return Math.min(75, highestSeverityWeight + additionalWeight);
}

function getCriticalityMultiplier(node) {
  const businessCriticality = Array.isArray(node.businessCriticality)
    ? node.businessCriticality
    : [];

  let multiplier = 1;

  for (const criticality of businessCriticality) {
    const normalized = String(criticality || '').toUpperCase();

    if (normalized === 'CRITICAL') {
      multiplier = Math.max(multiplier, 1.5);
    } else if (normalized === 'HIGH') {
      multiplier = Math.max(multiplier, 1.3);
    } else if (normalized === 'MEDIUM') {
      multiplier = Math.max(multiplier, 1.1);
    }
  }

  return multiplier;
}

function calculateRiskScores(graph) {
  for (const node of graph.values()) {
    const criticalityMultiplier = getCriticalityMultiplier(node);
    node.criticalityMultiplier = criticalityMultiplier;

    const vulnerabilityContribution = getVulnerabilityContribution(node.vulnerabilities);
    const licenseContribution = contributionFromLicenseLevel(node.licenseRisk?.level);
    const maintenanceContribution = contributionFromMaintenanceLevel(node.maintenanceRisk?.level);

    const baseRisk = Math.min(
      100,
      vulnerabilityContribution +
      Math.min(licenseContribution, 15) +
      Math.min(maintenanceContribution, 10)
    );

    const riskScore = Math.min(100, baseRisk * criticalityMultiplier);

    node.riskScore = Number(Math.max(0, riskScore).toFixed(2));

    for (const vulnerability of node.vulnerabilities || []) {
      vulnerability.riskFactors = {
        licenseRisk: licenseContribution,
        maintenanceRisk: maintenanceContribution,
        depthWeight: 0,
        criticalityMultiplier,
      };
    }
  }

  return graph;
}

module.exports = {
  calculateRiskScores,
};
