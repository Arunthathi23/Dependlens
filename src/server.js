const express = require('express');
const cors = require('cors');
const { loadCSV, loadJSON } = require("./engines/ingestion");
const dependencies = loadCSV("sbom_dependencies.csv");
const applicationsData = loadJSON("applications.json") || [];
const applicationsMap = new Map((applicationsData || []).map((application) => [application.app_id, application]));
const transitiveDependencies = loadJSON("transitive_dependencies.json") || [];
const vulnerabilityDb = loadJSON("vulnerability_db.json");
const licenseRules = loadJSON("license_rules.json");
const labels = loadCSV("dependency_labels.csv");
const directDependencySet = new Set(
  (Array.isArray(dependencies) ? dependencies : [])
    .filter((row) => String(row.dependency_type || '').toLowerCase() === 'direct')
    .map((row) => {
      const applicationId = normalizeText(row.application_id || row.app_id || '');
      const library = normalizeText(row.library || row.name || '');
      const version = normalizeText(row.version || '');
      return `${applicationId}::${library}::${version}`;
    })
);
const { buildGraph } = require("./engines/graph");
const { attachVulnerabilities } = require("./engines/vulnerability");
const { analyzeLicenses } = require("./engines/license");
const { analyzeMaintenance } = require("./engines/maintenance");
const { calculateRiskScores } = require("./engines/riskScore");
const { prioritizeRisks } = require("./engines/prioritization");
const { buildValidationSummary } = require("./engines/validation");

function normalizeText(value) {
  return String(value ?? '').trim();
}

function buildVulnerabilityInstances(graph) {
  const instances = [];
  const seenKeys = new Set();

  for (const node of graph.values()) {
    if (!Array.isArray(node.vulnerabilities) || node.vulnerabilities.length === 0) {
      continue;
    }

    const applicationDetails = Array.isArray(node.applicationDetails)
      ? node.applicationDetails
      : [];

    const applicationEntries = applicationDetails.length > 0
      ? applicationDetails
      : (Array.isArray(node.affectedApplications) ? node.affectedApplications : []).map((name) => ({
          app_id: '',
          name,
        }));

    for (const applicationDetail of applicationEntries) {
      const applicationId = normalizeText(applicationDetail.app_id || applicationDetail.application_id || '');
      const applicationLabel = normalizeText(applicationDetail.name || applicationDetail.application_name || 'Unknown Application');
      const directKey = `${applicationId}::${normalizeText(node.name)}::${normalizeText(node.version)}`;
      const riskType = directDependencySet.has(directKey)
        ? 'VULNERABLE_DEPENDENCY'
        : 'TRANSITIVE_VULNERABILITY';

      for (const vulnerability of node.vulnerabilities) {
        const cveId = normalizeText(vulnerability.cveId || vulnerability.cve_id || '');
        const instanceKey = `${applicationId}::${normalizeText(node.name)}::${normalizeText(node.version)}::${cveId}::${riskType}`;

        if (seenKeys.has(instanceKey)) {
          continue;
        }

        seenKeys.add(instanceKey);

        instances.push({
          application_id: applicationId,
          application_name: applicationLabel,
          library: normalizeText(node.name),
          version: normalizeText(node.version),
          severity: normalizeText(vulnerability.severity || 'UNKNOWN').toUpperCase(),
          cveId,
          risk_type: riskType,
        });
      }
    }
  }

  return instances;
}

const graph = buildGraph(dependencies, applicationsMap, transitiveDependencies);
attachVulnerabilities(graph, vulnerabilityDb, labels);
analyzeLicenses(graph, licenseRules);
analyzeMaintenance(graph);

const labelRows = Array.isArray(labels) ? labels : [];
for (const node of graph.values()) {
  const label = labelRows.find((row) => `${row.library}@${row.version}` === node.id);
  node.isExplicitlyCritical = Boolean(
    label &&
    String(label.is_risky || '').toLowerCase() === 'true' &&
    String(label.severity || '').toUpperCase() === 'CRITICAL'
  );
  node.labelSeverity = label?.severity || null;
  node.labelRiskType = label?.risk_type || null;
}

calculateRiskScores(graph);
prioritizeRisks(graph);
const vulnerabilityInstances = buildVulnerabilityInstances(graph);
const directVulnerabilities = vulnerabilityInstances.filter((instance) => instance.risk_type === 'VULNERABLE_DEPENDENCY').length;
const transitiveVulnerabilities = vulnerabilityInstances.filter((instance) => instance.risk_type === 'TRANSITIVE_VULNERABILITY').length;

graph.vulnerableInstances = vulnerabilityInstances;
graph.instanceSummary = {
  totalInstances: vulnerabilityInstances.length,
  directVulnerabilities,
  transitiveVulnerabilities,
};
console.log("Number of nodes:", graph.size);

console.log(
    "Backend pipeline initialized successfully."
);

const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'DependLens running' });
});

app.get("/api/graph", (req, res) => {
  const nodes = Array.from(graph.values());

  res.json(nodes);
});

app.get("/api/package/:id", (req, res) => {
  const node = graph.get(req.params.id);

  if (!node) {
    return res.status(404).json({
      error: "Package not found",
    });
  }

  res.json(node);
});

app.get("/api/priorities", (req, res) => {
  const nodes = Array.from(graph.values());

  const grouped = {
    immediate: [],
    sprint: [],
    monitor: [],
  };

  nodes.forEach((node) => {
    if (node.priority === "Fix Immediately") {
      grouped.immediate.push(node);
    } else if (node.priority === "Fix This Sprint") {
      grouped.sprint.push(node);
    } else {
      grouped.monitor.push(node);
    }
  });

  res.json(grouped);
});

app.get("/api/vulnerability-instances", (req, res) => {
  res.json({
    totalInstances: graph.instanceSummary.totalInstances,
    directVulnerabilities: graph.instanceSummary.directVulnerabilities,
    transitiveVulnerabilities: graph.instanceSummary.transitiveVulnerabilities,
    instances: graph.vulnerableInstances,
  });
});

app.get("/api/validation", (req, res) => {
  const labelRows = Array.isArray(labels) ? labels : [];
  const { summary, results } = buildValidationSummary(labelRows, graph, applicationsMap);

  res.json({
    summary,
    results,
  });
});

app.get("/api/stats", (req, res) => {
  const nodes = Array.from(graph.values());

  const malformedNodes = nodes.filter((node) => {
    return !node
      || !Array.isArray(node.vulnerabilities)
      || !Array.isArray(node.affectedApplications);
  });

  if (malformedNodes.length > 0) {
    console.warn(
      "[api/stats] malformed nodes:",
      malformedNodes.map((node) => ({
        id: node?.id,
        hasVulnerabilities: Array.isArray(node?.vulnerabilities),
        hasAffectedApplications: Array.isArray(node?.affectedApplications),
        priority: node?.priority,
      }))
    );
  }

  const vulnerableNodes = nodes.filter(
    (node) => Array.isArray(node?.vulnerabilities) && node.vulnerabilities.length > 0
  ).length;

  const vulnerableInstances = Array.isArray(graph.vulnerableInstances)
    ? graph.vulnerableInstances.length
    : Number(graph.instanceSummary?.totalInstances || 0);
  const stats = {
    totalPackages: nodes.length,

    vulnerablePackages: vulnerableInstances,

    criticalPackages: nodes.filter(
      (node) => node.priority === "Fix Immediately"
    ).length,

    applications: new Set(
      nodes.flatMap((node) => Array.isArray(node?.affectedApplications) ? node.affectedApplications : [])
    ).size,
  };

  res.json(stats);
});

const PORT = 5000;

app.listen(PORT, () => {
  console.log('Server running on port 5000');
});
