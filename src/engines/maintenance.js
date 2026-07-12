function analyzeMaintenance(graph) {
  const referenceDate = new Date('2026-07-11T00:00:00Z');

  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    
    const lastUpdated = new Date(`${node.lastUpdated}T00:00:00Z`);

    if (Number.isNaN(lastUpdated.getTime())) {
      node.maintenanceRisk = {
        level: 'High',
        message: 'Package appears unmaintained',
      };
      node.maintenanceStatus = 'Unmaintained';
      node.daysSinceLastUpdate = 9999;
      node.maintenanceScore = 100;
      node.maintenanceMessage = 'No update timeline recorded';
      continue;
    }

    const days = Math.floor((referenceDate - lastUpdated) / (1000 * 60 * 60 * 24));
    node.daysSinceLastUpdate = days;

    if (days <= 365) {
      node.maintenanceStatus = 'Healthy';
      node.maintenanceScore = 0;
      node.maintenanceMessage = 'Package actively maintained';
      node.maintenanceRisk = { level: 'Low', message: 'Active' };
    } else if (days <= 548) {
      node.maintenanceStatus = 'Aging';
      node.maintenanceScore = 30;
      node.maintenanceMessage = 'Package shows moderate inactivity';
      node.maintenanceRisk = { level: 'Medium', message: 'Aging' };
    } else if (days <= 730) {
      node.maintenanceStatus = 'Stale';
      node.maintenanceScore = 60;
      node.maintenanceMessage = 'Package approaching unmaintained status';
      node.maintenanceRisk = { level: 'Medium', message: 'Stale' };
    } else {
      node.maintenanceStatus = 'Unmaintained';
      node.maintenanceScore = 100;
      node.maintenanceMessage = 'Package is severely unmaintained';
      node.maintenanceRisk = { level: 'High', message: 'Unmaintained' };
    }
  }

  return graph;
}

module.exports = {
  analyzeMaintenance,
};
