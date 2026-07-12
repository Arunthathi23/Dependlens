// Security Narrative Generator Engine for DependLens

function generateSecurityNarrative(node) {
  const isDirect = node.depth === 0;
  const directText = isDirect ? "directly" : "transitive (indirect)";
  const appText = node.affectedApplications?.length > 0 
    ? `It affects ${node.affectedApplications.length} applications: [${node.affectedApplications.join(', ')}].` 
    : 'It is isolated and does not affect active services.';
    
  const vulnCount = node.vulnerabilities?.length || 0;
  let vulnText = "";
  if (vulnCount > 0) {
    const maxSev = node.vulnerabilities.reduce((max, v) => {
      const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0 };
      return rank[v.severity] > rank[max.severity] ? v : max;
    }, { severity: 'SAFE' }).severity;
    
    vulnText = `The library contains ${vulnCount} vulnerabilities, with the highest severity being ${maxSev}. CVEs: [${node.vulnerabilities.map(v => v.cveId).join(', ')}].`;
  } else {
    vulnText = "There are no known vulnerability CVEs associated with this package.";
  }

  const blastText = node.blastRadius >= 30 
    ? `A blast radius score of ${node.blastRadius} (${node.impactLevel}) indicates a highly connected exposure across your microservices.`
    : `A blast radius score of ${node.blastRadius} (${node.impactLevel}) suggests a low-risk blast surface.`;

  const patchText = node.remediationStatus === 'PATCH_AVAILABLE'
    ? `Remediation is feasible: an official patch is available. Upgrading to v${node.recommendedVersion} is recommended.`
    : "No official patch is currently available. Active mitigation and isolating network calls are required.";

  return `${node.name}@${node.version} is a ${directText} dependency. ${appText} ${vulnText} ${blastText} ${patchText}`;
}

module.exports = {
  generateSecurityNarrative
};
