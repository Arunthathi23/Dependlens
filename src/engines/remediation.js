// Remediation Advice Generator Engine for DependLens

function generateRemediation(node) {
  const isPatched = node.remediationStatus === 'PATCH_AVAILABLE';
  const hasVuln = node.vulnerabilities?.length > 0;
  
  let immediateAction = "";
  let recommendation = "";
  let urgency = "Low";
  let estimatedEffort = "Low";
  let remediationNarrative = "";

  if (!hasVuln) {
    immediateAction = "Monitor";
    recommendation = "No vulnerability action required. Maintain general package updates.";
    urgency = "Low";
    estimatedEffort = "Low";
    remediationNarrative = "This package is clean and free of vulnerabilities. Keep monitoring for future security advisories.";
  } else {
    urgency = node.priority === 'Fix Immediately' ? 'Critical' : (node.priority === 'Fix This Sprint' ? 'Medium' : 'Low');
    estimatedEffort = node.depth === 0 ? 'Low (Simple package bump)' : 'Medium (Requires parent update or code-level testing)';
    
    if (isPatched) {
      immediateAction = `Upgrade to v${node.recommendedVersion}`;
      recommendation = `Run package-lock resolutions or upgrade root parent dependency to ingest patch version v${node.recommendedVersion}`;
      remediationNarrative = `An official patch is available. Upgrading will resolve ${node.vulnerabilities.length} vulnerabilities. Estimated remediation difficulty is ${node.remediationDifficulty || 'Low'}.`;
    } else {
      immediateAction = "Mitigation Required";
      recommendation = "Perform code isolation, configure firewalls, or replace library with an actively maintained alternative.";
      remediationNarrative = `No official patch exists yet. Isolation is required. Urgency is ${urgency} due to exploitability and blast radius levels.`;
    }
  }

  return {
    immediateAction,
    recommendation,
    urgency,
    estimatedEffort,
    remediationNarrative
  };
}

module.exports = {
  generateRemediation
};
