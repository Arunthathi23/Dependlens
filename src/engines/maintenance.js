function analyzeMaintenance(graph) {
  const referenceDate = new Date('2026-07-11T00:00:00Z');
  const twoYearsAgo = new Date(referenceDate);
  twoYearsAgo.setUTCFullYear(referenceDate.getUTCFullYear() - 2);

  for (const node of graph.values()) {
    const lastUpdated = new Date(`${node.lastUpdated}T00:00:00Z`);

    if (Number.isNaN(lastUpdated.getTime())) {
      node.maintenanceRisk = {
        level: 'High',
        message: 'Package appears unmaintained',
      };
      continue;
    }

    if (lastUpdated < twoYearsAgo) {
      node.maintenanceRisk = {
        level: 'High',
        message: 'Package appears unmaintained',
      };
    } else {
      node.maintenanceRisk = {
        level: 'Low',
        message: 'Package actively maintained',
      };
    }
  }

  return graph;
}

module.exports = {
  analyzeMaintenance,
};
