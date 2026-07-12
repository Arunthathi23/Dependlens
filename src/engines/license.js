function normalizeLicense(license) {
  if (!license || !license.trim()) {
    return '';
  }

  const normalized = license.trim().toLowerCase();

  if (normalized === 'mit license' || normalized === 'mit') {
    return 'MIT';
  }

  return license.trim();
}

function analyzeLicenses(graph, licenseRules) {
  const categories = Array.isArray(licenseRules)
    ? licenseRules
    : Array.isArray(licenseRules?.license_categories)
      ? licenseRules.license_categories
      : [];

  const categoryMap = new Map();

  for (const rule of categories) {
    categoryMap.set(normalizeLicense(rule.license), rule);
  }

  for (const node of graph.values()) {
    const normalizedLicense = normalizeLicense(node.license);

    if (!normalizedLicense) {
      const applicationDetails = Array.isArray(node.applicationDetails) ? node.applicationDetails : [];
      const hasProprietaryApp = applicationDetails.length === 0 || applicationDetails.some(app => app.license_model === 'proprietary');
      node.licenseRisk = {
        level: hasProprietaryApp ? 'Unknown License Risk' : 'LOW',
        message: 'Missing license',
        compatibleWithProprietary: false,
        viral: false,
      };
      continue;
    }

    const matchedRule = categoryMap.get(normalizedLicense);

    if (!matchedRule) {
      const applicationDetails = Array.isArray(node.applicationDetails) ? node.applicationDetails : [];
      const hasProprietaryApp = applicationDetails.length === 0 || applicationDetails.some(app => app.license_model === 'proprietary');
      node.licenseRisk = {
        level: hasProprietaryApp ? 'Unknown License Risk' : 'LOW',
        message: `Unknown license: ${node.license}`,
        compatibleWithProprietary: false,
        viral: false,
      };
      continue;
    }

    const applicationDetails = Array.isArray(node.applicationDetails) ? node.applicationDetails : [];
    const hasProprietaryApp = applicationDetails.length === 0 || applicationDetails.some(app => app.license_model === 'proprietary');
    const isConflict = !matchedRule.compatible_with_proprietary && hasProprietaryApp;

    node.licenseRisk = {
      level: isConflict ? (matchedRule.risk_level || 'Unknown License Risk') : 'LOW',
      message: matchedRule.notes || `${matchedRule.category || matchedRule.license} license`,
      compatibleWithProprietary: Boolean(matchedRule.compatible_with_proprietary),
      viral: Boolean(matchedRule.viral),
    };
  }

  return graph;
}

module.exports = {
  analyzeLicenses,
};
