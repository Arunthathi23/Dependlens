// Business Impact Analyzer Engine for DependLens

function generateBusinessImpact(node) {
  const appsCount = node.affectedApplications?.length || 0;
  const hasVuln = node.vulnerabilities?.length > 0;
  
  let impactLevel = 'Low';
  if (appsCount >= 3 && hasVuln) impactLevel = 'Critical';
  else if (appsCount >= 2 && hasVuln) impactLevel = 'High';
  else if (hasVuln) impactLevel = 'Medium';

  const impactNarrative = `This package affects ${appsCount} applications, including critical upstream business microservices. Its operational blast radius is evaluated as ${node.impactLevel || 'Low'} due to dependency hierarchy position. A failure or compromise of this library carries a ${impactLevel} business impact rating.`;

  return {
    impactLevel,
    blastRadius: node.blastRadius || 0,
    affectedApplications: node.affectedApplications,
    impactNarrative
  };
}

module.exports = {
  generateBusinessImpact
};
