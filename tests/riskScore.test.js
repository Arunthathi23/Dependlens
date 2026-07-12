const assert = require('assert');
const { calculateRiskScores } = require('../src/engines/riskScore');
const { prioritizeRisks } = require('../src/engines/prioritization');

const graph = new Map([
  [
    'demo@1.0.0',
    {
      id: 'demo@1.0.0',
      name: 'demo',
      version: '1.0.0',
      license: 'GPL-3.0',
      lastUpdated: '2020-01-01',
      depth: 0,
      parents: [],
      children: [],
      paths: [],
      affectedApplications: ['CustomerPortal'],
      applicationDetails: [],
      businessCriticality: ['HIGH'],
      deployment: ['cloud'],
      department: ['Engineering'],
      owners: ['Owner'],
      vulnerabilities: [],
      criticalityMultiplier: 1.3,
      licenseRisk: { level: 'Critical', message: 'restrictive license' },
      maintenanceRisk: { level: 'High', message: 'stale package' },
      riskScore: 0,
      priority: 'Monitor',
    },
  ],
]);

calculateRiskScores(graph);
prioritizeRisks(graph);

const node = graph.get('demo@1.0.0');

assert.ok(node.riskScore < 60, `Expected score below 60, got ${node.riskScore}`);
assert.strictEqual(node.priority, 'Monitor', `Expected Monitor, got ${node.priority}`);

const criticalGraph = new Map([
  [
    'lombok@4.1.2',
    {
      id: 'lombok@4.1.2',
      name: 'lombok',
      version: '4.1.2',
      license: 'GPL-3.0',
      lastUpdated: '2020-01-01',
      depth: 0,
      parents: [],
      children: [],
      paths: [],
      affectedApplications: ['CustomerPortal'],
      applicationDetails: [],
      businessCriticality: ['HIGH'],
      deployment: ['cloud'],
      department: ['Engineering'],
      owners: ['Owner'],
      vulnerabilities: [
        {
          severity: 'CRITICAL',
          cvss_score: 9.9,
          cveId: 'CVE-2023-1002',
        },
      ],
      criticalityMultiplier: 1.3,
      licenseRisk: { level: 'Medium', message: 'review required' },
      maintenanceRisk: { level: 'High', message: 'stale package' },
      riskScore: 0,
      priority: 'Monitor',
    },
  ],
]);

calculateRiskScores(criticalGraph);
prioritizeRisks(criticalGraph);

const criticalNode = criticalGraph.get('lombok@4.1.2');
assert.ok(criticalNode.riskScore >= 80, `Expected score at least 80, got ${criticalNode.riskScore}`);
assert.strictEqual(criticalNode.priority, 'Fix Immediately', `Expected Fix Immediately, got ${criticalNode.priority}`);

console.log('risk scoring regression test passed');
