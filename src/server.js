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
const { analyzeSupplyChainAnomalies } = require("./engines/supplyChainAnomalies");
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
analyzeSupplyChainAnomalies(graph);

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

const { generateSecurityNarrative } = require("./engines/narrative");
const { generateAttackPaths } = require("./engines/attackPath");
const { generateRemediation } = require("./engines/remediation");
const { explainRisk } = require("./engines/explainRisk");
const { generateBusinessImpact } = require("./engines/businessImpact");

for (const node of graph.values()) {
  if (node.type === 'application') continue;
  node.securityNarrative = generateSecurityNarrative(node);
  node.attackAnalysis = generateAttackPaths(node);
  node.remediation = generateRemediation(node);
  node.riskExplanation = explainRisk(node);
  node.businessImpact = generateBusinessImpact(node);
}

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

app.get("/api/conflicts", (req, res) => {
  const conflicts = [];
  const seen = new Set();
  for (const node of graph.values()) {
    if (node.hasVersionConflict && !seen.has(node.name)) {
      seen.add(node.name);
      conflicts.push({
        package: node.name,
        versions: [node.version, ...node.conflictingVersions],
        affectedApplications: node.conflictApplications,
        severity: node.riskScore >= 70 ? 'CRITICAL' : (node.riskScore >= 40 ? 'HIGH' : 'MEDIUM')
      });
    }
  }
  res.json(conflicts);
});

app.get("/api/diamonds", (req, res) => {
  const diamonds = [];
  const seen = new Set();
  for (const node of graph.values()) {
    if (node.hasDiamondDependency && !seen.has(node.name)) {
      seen.add(node.name);
      diamonds.push({
        package: node.name,
        affectedApplications: node.affectedApplications,
        paths: node.diamondPaths
      });
    }
  }
  res.json(diamonds);
});

app.get("/api/blast-radius", (req, res) => {
  const list = [];
  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    list.push({
      package: node.id,
      blastRadius: node.blastRadius,
      impactLevel: node.impactLevel,
      affectedApplications: node.affectedApplications
    });
  }
  list.sort((a,b) => b.blastRadius - a.blastRadius);
  res.json(list);
});

app.get("/api/path-analysis", (req, res) => {
  const list = [];
  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    list.push({
      package: node.id,
      pathCount: node.pathCount || 1,
      affectedApplications: node.affectedApplications,
      compoundedRisk: node.compoundedRisk || node.riskScore
    });
  }
  list.sort((a,b) => b.pathCount - a.pathCount);
  res.json(list);
});

app.get("/api/popularity", (req, res) => {
  const list = [];
  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    list.push({
      package: node.id,
      popularityScore: node.popularityScore || 0,
      popularityLevel: node.popularityLevel || 'Low'
    });
  }
  list.sort((a,b) => b.popularityScore - a.popularityScore);
  res.json(list);
});

app.get("/api/dependency-importance", (req, res) => {
  const list = [];
  for (const node of graph.values()) {
    if (node.type === 'application') continue;
    list.push({
      package: node.id,
      importanceScore: node.importanceScore || 0,
      importanceLevel: node.importanceLevel || 'Low'
    });
  }
  list.sort((a,b) => b.importanceScore - a.importanceScore);
  res.json(list);
});

app.get("/api/ai-summary", (req, res) => {
  const nodes = Array.from(graph.values()).filter(n => n.type !== 'application');
  
  const sortedByRisk = [...nodes].sort((a,b) => (b.compoundedRisk || b.riskScore) - (a.compoundedRisk || a.riskScore));
  const mostDangerous = sortedByRisk[0];

  const appRiskSum = {};
  const appRiskCount = {};
  nodes.forEach(node => {
    if (Array.isArray(node.affectedApplications)) {
      node.affectedApplications.forEach(app => {
        appRiskSum[app] = (appRiskSum[app] || 0) + (node.riskScore || 0);
        appRiskCount[app] = (appRiskCount[app] || 0) + 1;
      });
    }
  });
  let highestRiskApp = "None";
  let maxAppRisk = -1;
  for (const app of Object.keys(appRiskSum)) {
    const avg = appRiskSum[app] / appRiskCount[app];
    if (avg > maxAppRisk) {
      maxAppRisk = avg;
      highestRiskApp = app;
    }
  }

  const sortedByBlast = [...nodes].sort((a,b) => (b.blastRadius || 0) - (a.blastRadius || 0));
  const largestBlast = sortedByBlast[0];

  const topRec = mostDangerous && mostDangerous.remediation 
    ? mostDangerous.remediation.recommendation 
    : "Maintain general package updates.";

  const totalPkgs = nodes.length;
  const vulnerableCount = nodes.filter(n => n.vulnerabilities?.length > 0).length;
  const criticalCount = nodes.filter(n => n.priority === 'Fix Immediately').length;
  const execSummary = `DependLens has audited your active software supply chain. Out of ${totalPkgs} monitored packages, we detected ${vulnerableCount} vulnerable packages, including ${criticalCount} critical remediation items requiring immediate turnaround. The highest operational risk is currently centered on ${mostDangerous ? mostDangerous.name : 'none'}. Implementation of patches and mitigation filters is advised to reduce transitive risk propagation.`;

  res.json({
    mostDangerousDependency: mostDangerous ? `${mostDangerous.name}@${mostDangerous.version}` : 'None',
    highestRiskApplication: highestRiskApp,
    largestBlastRadius: largestBlast ? `${largestBlast.name} (Blast Score: ${largestBlast.blastRadius})` : 'None',
    topRecommendation: topRec,
    executiveSummary: execSummary
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
