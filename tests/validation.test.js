const assert = require('assert');
const { buildValidationSummary } = require('../src/engines/validation');

const labelRows = [
  {
    application_id: 'app-1',
    library: 'requests',
    version: '2.31.0',
    severity: 'HIGH',
    is_risky: 'true',
    risk_type: 'VULNERABLE_DEPENDENCY',
    explanation: 'Direct vulnerable dependency',
  },
  {
    application_id: 'app-1',
    library: 'urllib3',
    version: '1.26.0',
    severity: 'CRITICAL',
    is_risky: 'true',
    risk_type: 'TRANSITIVE_VULNERABILITY',
    explanation: 'Transitive vulnerability',
  },
  {
    application_id: 'app-1',
    library: 'safe-package',
    version: '1.0.0',
    severity: 'LOW',
    is_risky: 'false',
    risk_type: 'VULNERABLE_DEPENDENCY',
    explanation: 'Safe package',
  },
];

const applicationsMap = new Map([
  ['app-1', { app_id: 'app-1', name: 'App 1' }],
]);

const graph = new Map([
  ['requests@2.31.0', { id: 'requests@2.31.0', name: 'requests', version: '2.31.0', priority: 'Fix This Sprint', vulnerabilities: [], applicationDetails: [{ app_id: 'app-1', name: 'App 1' }] }],
  ['urllib3@1.26.0', { id: 'urllib3@1.26.0', name: 'urllib3', version: '1.26.0', priority: 'Fix Immediately', vulnerabilities: [], applicationDetails: [{ app_id: 'app-1', name: 'App 1' }] }],
]);

graph.vulnerableInstances = [
  {
    application_id: 'app-1',
    application_name: 'App 1',
    library: 'requests',
    version: '2.31.0',
    severity: 'HIGH',
    cveId: 'CVE-1',
    risk_type: 'VULNERABLE_DEPENDENCY',
  },
  {
    application_id: 'app-1',
    application_name: 'App 1',
    library: 'urllib3',
    version: '1.26.0',
    severity: 'CRITICAL',
    cveId: 'CVE-2',
    risk_type: 'TRANSITIVE_VULNERABILITY',
  },
];

const { summary } = buildValidationSummary(labelRows, graph, applicationsMap);

assert.strictEqual(summary.expectedVulnerableInstances, 2);
assert.strictEqual(summary.predictedVulnerableInstances, 2);
assert.strictEqual(summary.vulnerabilityDetectionRate, 100);
assert.strictEqual(summary.precision, 100);
assert.strictEqual(summary.recall, 100);
assert.strictEqual(summary.f1, 100);

console.log('validation regression test passed');
