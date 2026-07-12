function normalizeText(value) {
  return String(value ?? '').trim();
}

function toExpectedRisk(severity, isRisky) {
  const normalizedSeverity = String(severity || '').toUpperCase();

  if (!isRisky) {
    return 'Monitor';
  }

  if (normalizedSeverity === 'CRITICAL') {
    return 'Fix Immediately';
  }

  if (normalizedSeverity === 'HIGH') {
    return 'Fix This Sprint';
  }

  return 'Monitor';
}

function toReadableSeverity(value) {
  const normalized = String(value || '').trim().toUpperCase();

  if (normalized === 'CRITICAL') {
    return 'Critical';
  }

  if (normalized === 'HIGH') {
    return 'High';
  }

  if (normalized === 'MEDIUM') {
    return 'Medium';
  }

  if (normalized === 'LOW') {
    return 'Low';
  }

  return 'Monitor';
}

function buildValidationSummary(labelRows, graph, applicationsMap = new Map()) {
  const rows = Array.isArray(labelRows) ? labelRows : [];
  const nodes = Array.from(graph.values());
  const vulnerableInstances = Array.isArray(graph.vulnerableInstances) ? graph.vulnerableInstances : [];

  const instanceLookup = new Map();

  for (const instance of vulnerableInstances) {
    const instanceKey = `${normalizeText(instance.application_id)}::${normalizeText(instance.library)}::${normalizeText(instance.version)}`;

    if (!instanceLookup.has(instanceKey)) {
      instanceLookup.set(instanceKey, []);
    }

    instanceLookup.get(instanceKey).push(instance);
  }

  const results = rows.map((row) => {
    const isRisky = String(row.is_risky || '').toLowerCase() === 'true';
    const riskType = normalizeText(row.risk_type).toUpperCase();
    const node = graph.get(`${row.library}@${row.version}`);
    const instanceKey = `${normalizeText(row.application_id)}::${normalizeText(row.library)}::${normalizeText(row.version)}`;
    const instanceMatches = instanceLookup.get(instanceKey) || [];
    const severity = String(
      row.severity || instanceMatches[0]?.severity || node?.vulnerabilities?.[0]?.severity || 'NONE'
    ).toUpperCase();
    const applicationName = normalizeText(applicationsMap.get(row.application_id)?.name || row.application_id);
    const predictedRisk = node?.priority || 'Monitor';
    const expectedRisk = toExpectedRisk(row.severity, isRisky);

    return {
      application_id: normalizeText(row.application_id),
      application_name: applicationName,
      library: normalizeText(row.library),
      version: normalizeText(row.version),
      severity,
      risk_type: riskType,
      is_risky: isRisky,
      predictedRisk,
      expectedRisk,
      explanation: row.explanation || '',
      correct: predictedRisk === expectedRisk,
    };
  });

  const totalEvaluated = rows.length;
  const correctPredictions = results.filter((row) => row.correct).length;
  const incorrectPredictions = Math.max(totalEvaluated - correctPredictions, 0);
  const accuracy = totalEvaluated ? (correctPredictions / totalEvaluated) * 100 : 0;

  const expectedVulnerabilityKeys = new Set(
    rows
      .filter((row) => {
        const isRisky = String(row.is_risky || '').toLowerCase() === 'true';
        const riskType = normalizeText(row.risk_type).toUpperCase();

        return isRisky && (
          riskType === 'VULNERABLE_DEPENDENCY' ||
          riskType === 'TRANSITIVE_VULNERABILITY'
        );
      })
      .map((row) => `${normalizeText(row.application_id)}::${normalizeText(row.library)}::${normalizeText(row.version)}`)
  );

  const predictedVulnerabilityKeys = new Set(
    vulnerableInstances.map((instance) => {
      return `${normalizeText(instance.application_id)}::${normalizeText(instance.library)}::${normalizeText(instance.version)}`;
    })
  );
  const predictedVulnerableInstances = vulnerableInstances.length;
  const expectedVulnerableInstances = expectedVulnerabilityKeys.size;
  const truePositive = Array.from(expectedVulnerabilityKeys).filter((key) => predictedVulnerabilityKeys.has(key)).length;
  const falsePositive = predictedVulnerabilityKeys.size - truePositive;
  const falseNegative = expectedVulnerableInstances - truePositive;

  const vulnerabilityDetectionRate = expectedVulnerableInstances > 0
    ? Math.min(100, (predictedVulnerableInstances / expectedVulnerableInstances) * 100)
    : 0;

  const expectedTransitiveKeys = new Set(
    rows
      .filter((row) => {
        const isRisky = String(row.is_risky || '').toLowerCase() === 'true';
        const riskType = normalizeText(row.risk_type).toUpperCase();

        return isRisky && riskType === 'TRANSITIVE_VULNERABILITY';
      })
      .map((row) => `${normalizeText(row.application_id)}::${normalizeText(row.library)}::${normalizeText(row.version)}`)
  );

  const predictedTransitiveKeys = new Set(
    vulnerableInstances
      .filter((instance) => normalizeText(instance.risk_type).toUpperCase() === 'TRANSITIVE_VULNERABILITY')
      .map((instance) => `${normalizeText(instance.application_id)}::${normalizeText(instance.library)}::${normalizeText(instance.version)}`)
  );

  const predictedTransitiveVulnerabilities = Array.from(expectedTransitiveKeys).filter((key) => predictedTransitiveKeys.has(key)).length;
  const transitiveResolutionRate = Math.min(
    100,
    expectedTransitiveKeys.size > 0
      ? (predictedTransitiveVulnerabilities / expectedTransitiveKeys.size) * 100
      : 0
  );

  const expectedLicenseKeys = new Set(
    rows
      .filter((row) => {
        const isRisky = String(row.is_risky || '').toLowerCase() === 'true';
        const riskType = normalizeText(row.risk_type).toUpperCase();

        return isRisky && (
          riskType === 'LICENSE_CONFLICT' ||
          riskType === 'TRANSITIVE_LICENSE_CONFLICT'
        );
      })
      .map((row) => `${normalizeText(row.application_id)}::${normalizeText(row.library)}::${normalizeText(row.version)}`)
  );

  const predictedLicenseKeys = new Set();

  for (const node of nodes) {
    const normalizedLicenseLevel = normalizeText(node.licenseRisk?.level).toUpperCase();

    if (normalizedLicenseLevel !== 'HIGH' && normalizedLicenseLevel !== 'CRITICAL') {
      continue;
    }

    const applicationEntries = Array.isArray(node.applicationDetails) && node.applicationDetails.length > 0
      ? node.applicationDetails
      : (Array.isArray(node.affectedApplications) ? node.affectedApplications.map((name) => ({ app_id: '', name })) : []);

    for (const applicationDetail of applicationEntries) {
      const applicationId = normalizeText(applicationDetail.app_id || applicationDetail.application_id || '');
      const key = `${applicationId}::${normalizeText(node.name || node.id || '')}::${normalizeText(node.version)}`;

      predictedLicenseKeys.add(key);
    }
  }

  const detectedLicenseConflicts = Array.from(expectedLicenseKeys).filter((key) => predictedLicenseKeys.has(key)).length;
  const licenseDetectionRate = expectedLicenseKeys.size > 0
    ? (detectedLicenseConflicts / expectedLicenseKeys.size) * 100
    : 0;

  const falsePositiveRate = totalEvaluated
    ? (incorrectPredictions / totalEvaluated) * 100
    : 0;

  const precision = predictedVulnerabilityKeys.size > 0
    ? (truePositive / predictedVulnerabilityKeys.size) * 100
    : 0;

  const recall = expectedVulnerableInstances > 0
    ? (truePositive / expectedVulnerableInstances) * 100
    : 0;

  const f1 = precision + recall > 0
    ? (2 * precision * recall) / (precision + recall)
    : 0;

  const detectionConfidence = Math.min(100, Math.max(0, ((accuracy + vulnerabilityDetectionRate) / 2)));

  const severityFrequency = results.reduce((counts, row) => {
    const severity = String(row.severity || '').toUpperCase();

    if (!counts[severity]) {
      counts[severity] = 0;
    }

    counts[severity] += 1;
    return counts;
  }, {});

  const dominantSeverity = Object.entries(severityFrequency)
    .sort((left, right) => right[1] - left[1])[0]?.[0] || 'NONE';

  const summary = {
    totalEvaluated,
    correctPredictions,
    incorrectPredictions,
    accuracy,
    expectedVulnerableInstances,
    predictedVulnerableInstances,
    vulnerabilityDetectionRate,
    transitiveResolutionRate,
    licenseDetectionRate,
    falsePositiveRate,
    precision,
    recall,
    f1,
    riskScoreAccuracy: accuracy,
    detectionConfidence,
    severityLevel: toReadableSeverity(dominantSeverity),
    explanation: results.find((row) => row.explanation)?.explanation || '',
  };

  return {
    summary,
    results,
  };
}

module.exports = {
  buildValidationSummary,
};
