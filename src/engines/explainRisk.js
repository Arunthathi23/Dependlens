// Risk Score Explainer Engine for DependLens

function explainRisk(node) {
  const vulns = node.vulnerabilities || [];
  let vulnerabilityContribution = 0;
  let exploitabilityContribution = 0;
  
  vulns.forEach(v => {
    const sev = String(v.severity).toUpperCase();
    const w = { CRITICAL: 80, HIGH: 55, MEDIUM: 30, LOW: 15 }[sev] || 0;
    vulnerabilityContribution = Math.max(vulnerabilityContribution, w);
    
    const exp = String(v.exploitability).toUpperCase();
    const ew = { HIGH: 10, MEDIUM: 5, LOW: 2 }[exp] || 0;
    exploitabilityContribution = Math.max(exploitabilityContribution, ew);
  });

  const maintenanceContribution = node.maintenanceScore || 0;
  
  const licenseLevel = String(node.licenseRisk?.level || '').toUpperCase();
  const licenseContribution = { CRITICAL: 15, HIGH: 10, MEDIUM: 5 }[licenseLevel] || 0;

  const pathCount = node.pathCount || 1;
  const pathContribution = (pathCount - 1) * 3;

  const criticalityMultiplier = node.criticalityMultiplier || 1.0;

  const finalScoreExplanation = `Base vulnerability risk of +${vulnerabilityContribution} combined with +${exploitabilityContribution} exploitability offset, +${maintenanceContribution} maintenance risk, and +${licenseContribution} copyleft risk. Multiplied by a factor of x${criticalityMultiplier} for business criticality.`;

  return {
    vulnerabilityContribution,
    exploitabilityContribution,
    maintenanceContribution,
    licenseContribution,
    pathContribution,
    criticalityMultiplier,
    finalScoreExplanation
  };
}

module.exports = {
  explainRisk
};
