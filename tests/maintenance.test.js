const assert = require('assert');
const { analyzeMaintenance } = require('../src/engines/maintenance');

function runMaintenanceTests() {
  // Test case 1: 25 months ago
  const node25 = {
    id: 'pkg-25@1.0.0',
    name: 'pkg-25',
    version: '1.0.0',
    lastUpdated: '2024-06-11',
    maintenanceStatus: '',
    maintenanceRisk: {}
  };

  // Test case 2: 18 months ago (last updated 2025-01-15)
  const node18 = {
    id: 'unknown-parser@1.0.0',
    name: 'unknown-parser',
    version: '1.0.0',
    lastUpdated: '2025-01-15',
    maintenanceStatus: '',
    maintenanceRisk: {}
  };

  // Test case 3: 2 years and 1 day ago (731 days ago)
  const node2Years1Day = {
    id: 'pkg-edge@1.0.0',
    name: 'pkg-edge',
    version: '1.0.0',
    lastUpdated: '2024-07-10',
    maintenanceStatus: '',
    maintenanceRisk: {}
  };

  const graph = new Map([
    [node25.id, node25],
    [node18.id, node18],
    [node2Years1Day.id, node2Years1Day]
  ]);

  analyzeMaintenance(graph);

  let allPassed = true;

  // Case 1 Check
  try {
    assert.strictEqual(node25.maintenanceStatus, 'Unmaintained');
    console.log('Case 1 (25 months ago): PASS');
  } catch (err) {
    console.log('Case 1 (25 months ago): FAIL - expected Unmaintained, got', node25.maintenanceStatus);
    allPassed = false;
  }

  // Case 2 Check
  try {
    assert.notStrictEqual(node18.maintenanceStatus, 'Unmaintained');
    assert.notStrictEqual(node18.maintenanceStatus, 'Stale');
    console.log('Case 2 (18 months ago): PASS');
  } catch (err) {
    console.log('Case 2 (18 months ago): FAIL - expected not Unmaintained/Stale, got', node18.maintenanceStatus);
    allPassed = false;
  }

  // Case 3 Check
  try {
    assert.strictEqual(node2Years1Day.maintenanceStatus, 'Unmaintained');
    console.log('Case 3 (2 years and 1 day ago): PASS');
  } catch (err) {
    console.log('Case 3 (2 years and 1 day ago): FAIL - expected Unmaintained, got', node2Years1Day.maintenanceStatus);
    allPassed = false;
  }

  if (allPassed) {
    console.log('All maintenance boundary tests PASSED.');
  } else {
    console.error('Some maintenance boundary tests FAILED.');
    process.exit(1);
  }
}

runMaintenanceTests();
