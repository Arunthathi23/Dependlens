// Attack Path Explainer Engine for DependLens

function generateAttackPaths(node) {
  const pathCount = node.pathCount || 1;
  const dependencyChains = node.diamondPaths || node.dependencyPaths || [];
  
  let chainExplanation = "";
  if (node.depth === 0) {
    chainExplanation = `${node.name} is imported directly by applications. The attack path is minimal, requiring immediate package update in the root manifest files.`;
  } else {
    chainExplanation = `${node.name} is nested deeply as a transitive dependency. It enters your system via parent packages: [${node.parents?.join(', ')}]. It is reachable through ${pathCount} unique dependency chains. Due to multiple incoming paths, the exposure of any underlying vulnerability is compounded.`;
  }

  return {
    dependencyChains,
    pathCount,
    chainExplanation
  };
}

module.exports = {
  generateAttackPaths
};
