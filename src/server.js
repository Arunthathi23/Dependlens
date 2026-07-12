const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

// Create uploads folder if not exists
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}
const upload = multer({ dest: 'uploads/' });

const { loadCSV, loadJSON } = require("./engines/ingestion");
const { buildGraph } = require("./engines/graph");
const { attachVulnerabilities } = require("./engines/vulnerability");
const { analyzeLicenses } = require("./engines/license");
const { analyzeMaintenance } = require("./engines/maintenance");
const { analyzeSupplyChainAnomalies } = require("./engines/supplyChainAnomalies");
const { calculateRiskScores } = require("./engines/riskScore");
const { prioritizeRisks } = require("./engines/prioritization");
const { buildValidationSummary } = require("./engines/validation");

function normalizeText(value) {
  if (value === null || value === undefined) return '';
  return String(value).trim();
}

function normalizeSeverity(value) {
  if (!value) return 'SAFE';
  const s = String(value).trim().toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'].includes(s)) return s;
  return 'SAFE';
}

function normalizeLicense(value) {
  if (!value) return 'UNKNOWN';
  return String(value).trim().toUpperCase();
}

function normalizeVersion(value) {
  if (!value) return '0.0.0';
  return String(value).trim();
}

function normalizeRiskType(value) {
  if (!value) return 'TRANSITIVE_VULNERABILITY';
  const r = String(value).trim().toUpperCase();
  if (r === 'VULNERABLE_DEPENDENCY' || r === 'DIRECT') return 'VULNERABLE_DEPENDENCY';
  return 'TRANSITIVE_VULNERABILITY';
}

function loadAndNormalizeData(applicationsData, dependencies, vulnerabilityDb, licenseRules, transitiveDependencies, labelsData) {
  if (!Array.isArray(applicationsData)) {
    throw new Error("applications.json must be a JSON array.");
  }
  for (const appItem of applicationsData) {
    if (appItem.app_id === undefined || appItem.name === undefined || appItem.criticality === undefined) {
      throw new Error("Each application entry in applications.json must contain 'app_id', 'name', and 'criticality'.");
    }
  }

  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    throw new Error("sbom_dependencies.csv is empty or invalid.");
  }
  const firstDep = dependencies[0];
  if (firstDep.application_id === undefined || firstDep.library === undefined || firstDep.version === undefined || firstDep.dependency_type === undefined) {
    throw new Error("sbom_dependencies.csv must contain headers: 'application_id', 'library', 'version', 'dependency_type'.");
  }

  if (!Array.isArray(vulnerabilityDb)) {
    throw new Error("vulnerability_db.json must be a JSON array.");
  }
  const normalizedVulns = vulnerabilityDb.map(vuln => {
    const pkg = vuln.package || vuln.library || vuln.name;
    const affected = vuln.affectedVersions || vuln.affected_versions || vuln.version;
    const cve = vuln.cveId || vuln.cve_id || '';
    const sev = vuln.severity || 'UNKNOWN';
    const cvss = vuln.cvss_score ?? vuln.cvss ?? vuln.cvssScore ?? 0;
    const exploit = vuln.exploitability || 'UNKNOWN';
    const patch = vuln.patch_available ?? vuln.patchAvailable ?? false;
    const pubDate = vuln.published_date || vuln.publishedDate || '';
    const fixedVer = vuln.fixed_version || vuln.fixedVersion || '';
    const desc = vuln.description || '';

    if (pkg === undefined || affected === undefined || vuln.severity === undefined) {
      throw new Error("Each vulnerability entry in vulnerability_db.json must contain package/library identifier, affectedVersions, and severity.");
    }
    
    const normPkg = normalizeText(pkg);
    const normAffected = normalizeText(affected);
    const normCve = normalizeText(cve);
    const normSev = normalizeSeverity(sev);

    return {
      package: normPkg,
      library: normPkg,
      package_name: normPkg,
      
      affectedVersions: normAffected,
      affected_versions: normAffected,
      version: normAffected,
      
      cveId: normCve,
      cve_id: normCve,
      
      severity: normSev,
      
      cvss: cvss,
      cvss_score: cvss,
      cvssScore: cvss,
      
      exploitability: exploit,
      
      patch_available: patch,
      patchAvailable: patch,
      
      published_date: pubDate,
      publishedDate: pubDate,
      
      fixed_version: fixedVer,
      fixedVersion: fixedVer,
      
      description: desc
    };
  });

  if (!Array.isArray(licenseRules)) {
    throw new Error("license_rules.json must be a JSON array.");
  }
  const normalizedLicenses = licenseRules.map(lic => {
    const name = lic.license;
    const risk = lic.risk_level || lic.level;

    if (name === undefined || risk === undefined) {
      throw new Error("Each license entry in license_rules.json must contain 'license' and 'risk_level'.");
    }
    return {
      ...lic,
      license: normalizeText(name),
      risk_level: normalizeSeverity(risk)
    };
  });

  const normalizedLabels = (labelsData || []).map(label => {
    if (label.application_id === undefined || label.library === undefined || label.version === undefined || label.is_risky === undefined || label.risk_type === undefined || label.severity === undefined) {
      throw new Error("dependency_labels.csv must contain headers: 'application_id', 'library', 'version', 'is_risky', 'risk_type', 'severity'.");
    }
    return {
      ...label,
      application_id: normalizeText(label.application_id),
      library: normalizeText(label.library),
      version: normalizeText(label.version),
      is_risky: normalizeText(label.is_risky),
      risk_type: normalizeRiskType(label.risk_type),
      severity: normalizeSeverity(label.severity)
    };
  });

  const normalizedDeps = dependencies.map(dep => {
    return {
      ...dep,
      application_id: normalizeText(dep.application_id),
      library: normalizeText(dep.library),
      version: normalizeVersion(dep.version),
      dependency_type: normalizeText(dep.dependency_type)
    };
  });

  return {
    appsData: applicationsData,
    depsData: normalizedDeps,
    vulnsData: normalizedVulns,
    licData: normalizedLicenses,
    transData: transitiveDependencies || [],
    labelsData: normalizedLabels
  };
}

// Global mutable references for active dataset
let currentGraph = null;
let currentVulnerabilityInstances = [];
let currentInstanceSummary = {};
let currentApplicationsMap = new Map();
let currentLabels = [];
let currentStats = {};
let currentPriorities = {};
let currentValidation = {};
let directDependencySet = new Set();

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

function runPipeline(dependencies, applicationsData, transitiveDependencies, vulnerabilityDb, licenseRules, labelsData) {
  const normalized = loadAndNormalizeData(applicationsData, dependencies, vulnerabilityDb, licenseRules, transitiveDependencies, labelsData);
  applicationsData = normalized.appsData;
  dependencies = normalized.depsData;
  vulnerabilityDb = normalized.vulnsData;
  licenseRules = normalized.licData;
  transitiveDependencies = normalized.transData;
  labelsData = normalized.labelsData;

  const appsMap = new Map((applicationsData || []).map((application) => [application.app_id, application]));
  
  // Re-build directDependencySet
  directDependencySet = new Set(
    (Array.isArray(dependencies) ? dependencies : [])
      .filter((row) => String(row.dependency_type || '').toLowerCase() === 'direct')
      .map((row) => {
        const applicationId = normalizeText(row.application_id || row.app_id || '');
        const library = normalizeText(row.library || row.name || '');
        const version = normalizeText(row.version || '');
        return `${applicationId}::${library}::${version}`;
      })
  );

  const g = buildGraph(dependencies, appsMap, transitiveDependencies);
  attachVulnerabilities(g, vulnerabilityDb, labelsData);
  analyzeLicenses(g, licenseRules);
  analyzeMaintenance(g);
  analyzeSupplyChainAnomalies(g);

  const labelRows = Array.isArray(labelsData) ? labelsData : [];
  for (const node of g.values()) {
    const label = labelRows.find((row) => `${row.library}@${row.version}` === node.id);
    node.isExplicitlyCritical = Boolean(
      label &&
      String(label.is_risky || '').toLowerCase() === 'true' &&
      String(label.severity || '').toUpperCase() === 'CRITICAL'
    );
    node.labelSeverity = label?.severity || null;
    node.labelRiskType = label?.risk_type || null;
  }

  calculateRiskScores(g);
  prioritizeRisks(g);

  // Run AI explainable intelligence explainers
  const { generateSecurityNarrative } = require("./engines/narrative");
  const { generateAttackPaths } = require("./engines/attackPath");
  const { generateRemediation } = require("./engines/remediation");
  const { explainRisk } = require("./engines/explainRisk");
  const { generateBusinessImpact } = require("./engines/businessImpact");

  for (const node of g.values()) {
    if (node.type === 'application') continue;
    node.securityNarrative = generateSecurityNarrative(node);
    node.attackAnalysis = generateAttackPaths(node);
    node.remediation = generateRemediation(node);
    node.riskExplanation = explainRisk(node);
    node.businessImpact = generateBusinessImpact(node);
  }

  const vInstances = buildVulnerabilityInstances(g);
  const directVulns = vInstances.filter((instance) => instance.risk_type === 'VULNERABLE_DEPENDENCY').length;
  const transitiveVulns = vInstances.filter((instance) => instance.risk_type === 'TRANSITIVE_VULNERABILITY').length;

  g.vulnerableInstances = vInstances;
  g.instanceSummary = {
    totalInstances: vInstances.length,
    directVulnerabilities: directVulns,
    transitiveVulnerabilities: transitiveVulns,
  };

  // Compute stats
  const nodesList = Array.from(g.values());
  const vInstancesLen = vInstances.length;
  const criticalCount = nodesList.filter((node) => node.priority === "Fix Immediately").length;
  const appsCount = new Set(
    nodesList.flatMap((node) => Array.isArray(node?.affectedApplications) ? node.affectedApplications : [])
  ).size;

  const calculatedStats = {
    totalPackages: nodesList.length,
    vulnerablePackages: vInstancesLen,
    criticalPackages: criticalCount,
    applications: appsCount,
  };

  // Compute priorities
  const groupedPriorities = {
    immediate: [],
    sprint: [],
    monitor: [],
  };
  nodesList.forEach((node) => {
    if (node.priority === "Fix Immediately") {
      groupedPriorities.immediate.push(node);
    } else if (node.priority === "Fix This Sprint") {
      groupedPriorities.sprint.push(node);
    } else {
      groupedPriorities.monitor.push(node);
    }
  });

  const valSummary = buildValidationSummary(labelRows, g, appsMap);

  // Compute AI summary
  const nodes = Array.from(g.values()).filter(n => n.type !== 'application');
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
  const criticalCountAI = nodes.filter(n => n.priority === 'Fix Immediately').length;
  const execSummary = `DependLens has audited your active software supply chain. Out of ${totalPkgs} monitored packages, we detected ${vulnerableCount} vulnerable packages, including ${criticalCountAI} critical remediation items requiring immediate turnaround. The highest operational risk is currently centered on ${mostDangerous ? mostDangerous.name : 'none'}. Implementation of patches and mitigation filters is advised to reduce transitive risk propagation.`;

  const aiSummary = {
    mostDangerousDependency: mostDangerous ? `${mostDangerous.name}@${mostDangerous.version}` : 'None',
    highestRiskApplication: highestRiskApp,
    largestBlastRadius: largestBlast ? `${largestBlast.name} (Blast Score: ${largestBlast.blastRadius})` : 'None',
    topRecommendation: topRec,
    executiveSummary: execSummary
  };

  // Pipeline Self-Check Verification
  const licenseConflictsCount = Array.from(g.values()).filter(node => node.licenseRisk?.level && node.licenseRisk.level !== 'SAFE').length;
  const unmaintainedPackagesCount = Array.from(g.values()).filter(node => node.maintenanceStatus === 'Unmaintained').length;

  console.log({
    applications: appsCount,
    dependencies: dependencies.length,
    graphNodes: nodesList.length,
    vulnerablePackages: vInstancesLen,
    transitiveVulnerabilities: transitiveVulns,
    licenseConflicts: licenseConflictsCount,
    unmaintainedPackages: unmaintainedPackagesCount,
    validationMetrics: valSummary.summary
  });

  // Update global mutable references
  currentGraph = g;
  currentVulnerabilityInstances = vInstances;
  currentInstanceSummary = g.instanceSummary;
  currentApplicationsMap = appsMap;
  currentLabels = labelRows;
  currentStats = calculatedStats;
  currentPriorities = groupedPriorities;
  currentValidation = valSummary;

  return {
    stats: currentStats,
    priorities: currentPriorities,
    validation: currentValidation,
    graph: Array.from(g.values()),
    vulnerabilityInstances: currentVulnerabilityInstances,
    summary: currentInstanceSummary,
    aiSummary
  };
}

// Ingestion of fallback/bundled sample dataset
function resetToDefault() {
  const dependencies = loadCSV("sbom_dependencies.csv");
  const applicationsData = loadJSON("applications.json") || [];
  const transitiveDependencies = loadJSON("transitive_dependencies.json") || [];
  const vulnerabilityDb = loadJSON("vulnerability_db.json");
  const licenseRules = loadJSON("license_rules.json");
  const labels = loadCSV("dependency_labels.csv");

  runPipeline(dependencies, applicationsData, transitiveDependencies, vulnerabilityDb, licenseRules, labels);
}

// Run default pipeline configuration
resetToDefault();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'DependLens running' });
});

app.get("/api/graph", (req, res) => {
  res.json(Array.from(currentGraph.values()));
});

app.get("/api/package/:id", (req, res) => {
  const node = currentGraph.get(req.params.id);
  if (!node) {
    return res.status(404).json({ error: "Package not found" });
  }
  res.json(node);
});

app.get("/api/priorities", (req, res) => {
  res.json(currentPriorities);
});

app.get("/api/vulnerability-instances", (req, res) => {
  res.json({
    totalInstances: currentInstanceSummary.totalInstances,
    directVulnerabilities: currentInstanceSummary.directVulnerabilities,
    transitiveVulnerabilities: currentInstanceSummary.transitiveVulnerabilities,
    instances: currentVulnerabilityInstances,
  });
});

app.get("/api/validation", (req, res) => {
  res.json(currentValidation);
});

app.get("/api/conflicts", (req, res) => {
  const conflicts = [];
  const seen = new Set();
  for (const node of currentGraph.values()) {
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
  for (const node of currentGraph.values()) {
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
  for (const node of currentGraph.values()) {
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
  for (const node of currentGraph.values()) {
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
  for (const node of currentGraph.values()) {
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
  for (const node of currentGraph.values()) {
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
  const nodes = Array.from(currentGraph.values()).filter(n => n.type !== 'application');
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
  res.json(currentStats);
});

app.post("/api/reset", (req, res) => {
  resetToDefault();
  res.json({ status: 'success', message: 'Reset to sample dataset complete' });
});

app.post("/api/analyze", upload.fields([
  { name: 'applications', maxCount: 1 },
  { name: 'dependencies', maxCount: 1 },
  { name: 'vulnerabilities', maxCount: 1 },
  { name: 'licenses', maxCount: 1 },
  { name: 'transitiveDependencies', maxCount: 1 },
  { name: 'labels', maxCount: 1 }
]), (req, res) => {
  console.log("Uploaded files:", req.files);
  console.log("Applications path:", req.files?.applications?.[0]?.path);

  if (!req.files || !req.files.applications || !req.files.dependencies || !req.files.vulnerabilities || !req.files.licenses) {
    return res.status(400).json({ error: "Missing required files. Please upload applications, dependencies, vulnerabilities, and licenses." });
  }

  const appsFile = req.files.applications[0];
  const depsFile = req.files.dependencies[0];
  const vulnsFile = req.files.vulnerabilities[0];
  const licFile = req.files.licenses[0];
  const transFile = req.files.transitiveDependencies ? req.files.transitiveDependencies[0] : null;
  const labelsFile = req.files.labels ? req.files.labels[0] : null;

  try {
    const appsPath = path.resolve(appsFile.path);
    const depsPath = path.resolve(depsFile.path);
    const vulnsPath = path.resolve(vulnsFile.path);
    const licPath = path.resolve(licFile.path);
    const transPath = transFile ? path.resolve(transFile.path) : null;
    const labelsPath = labelsFile ? path.resolve(labelsFile.path) : null;

    const appsData = loadJSON(appsPath);
    const depsData = loadCSV(depsPath);
    const vulnsData = loadJSON(vulnsPath);
    const licData = loadJSON(licPath);
    const transData = transPath ? loadJSON(transPath) : [];
    const labelsData = labelsPath ? loadCSV(labelsPath) : [];

    console.log("Applications type:", typeof appsData);
    console.log("Is array:", Array.isArray(appsData));
    console.log("Applications preview:", appsData);

    // Schema validations
    if (!Array.isArray(appsData)) {
      throw new Error("applications.json must be a JSON array.");
    }
    for (const appItem of appsData) {
      if (appItem.app_id === undefined || appItem.name === undefined || appItem.criticality === undefined) {
        throw new Error("Each application entry in applications.json must contain 'app_id', 'name', and 'criticality'.");
      }
    }

    if (!Array.isArray(depsData) || depsData.length === 0) {
      throw new Error("sbom_dependencies.csv is empty or invalid.");
    }
    const firstDep = depsData[0];
    if (firstDep.application_id === undefined || firstDep.library === undefined || firstDep.version === undefined) {
      throw new Error("sbom_dependencies.csv must contain headers: 'application_id', 'library', 'version'.");
    }

    if (!Array.isArray(vulnsData)) {
      throw new Error("vulnerability_db.json must be a JSON array.");
    }
    for (const vulnItem of vulnsData) {
      const hasPkg = vulnItem.package !== undefined || vulnItem.library !== undefined;
      const hasVers = vulnItem.affectedVersions !== undefined || vulnItem.affected_versions !== undefined;
      const hasSev = vulnItem.severity !== undefined;
      if (!hasPkg || !hasVers || !hasSev) {
        throw new Error("Each vulnerability entry in vulnerability_db.json must contain package/library identifier, affectedVersions/affected_versions, and severity.");
      }
    }

    if (!Array.isArray(licData)) {
      throw new Error("license_rules.json must be a JSON array.");
    }
    for (const licItem of licData) {
      if (licItem.license === undefined || licItem.risk_level === undefined) {
        throw new Error("Each license entry in license_rules.json must contain 'license' and 'risk_level'.");
      }
    }

    console.log("SBOM upload validation successful");

    const result = runPipeline(depsData, appsData, transData, vulnsData, licData, labelsData);

    res.json({
      status: 'success',
      ...result
    });

  } catch (err) {
    res.status(400).json({ error: err.message });
  } finally {
    const deleteSafe = (f) => { if (f && f.path && fs.existsSync(f.path)) fs.unlinkSync(f.path); };
    deleteSafe(appsFile);
    deleteSafe(depsFile);
    deleteSafe(vulnsFile);
    deleteSafe(licFile);
    deleteSafe(transFile);
    deleteSafe(labelsFile);
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log('Server running on port 5000');
});
