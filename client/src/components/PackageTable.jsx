import { Fragment, useEffect, useMemo, useState } from 'react';
import { getPriorities } from '../services/api';
import './PackageTable.css';

function flattenPriorities(data) {
  if (!data || typeof data !== 'object') {
    return [];
  }

  return [
    ...(Array.isArray(data.immediate) ? data.immediate : []),
    ...(Array.isArray(data.sprint) ? data.sprint : []),
    ...(Array.isArray(data.monitor) ? data.monitor : []),
  ];
}

function getSeverity(node) {
  const vulns = Array.isArray(node?.vulnerabilities) ? node.vulnerabilities : [];
  if (vulns.length === 0) return 'Safe';

  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0, UNKNOWN: 0 };
  let maxRank = 0;
  let maxSev = 'Safe';

  for (const v of vulns) {
    const s = String(v.severity || '').toUpperCase();
    const rank = severityRank[s] || 0;
    if (rank > maxRank) {
      maxRank = rank;
      maxSev = s;
    }
  }

  if (maxSev === 'CRITICAL') return 'Critical';
  if (maxSev === 'HIGH') return 'High';
  if (maxSev === 'MEDIUM') return 'Medium';
  if (maxSev === 'LOW') return 'Low';
  return 'Safe';
}

function getSeverityClass(severity) {
  return `severity-chip severity-chip--${severity.toLowerCase()}`;
}

function getPlainEnglishExplanation(node, severity) {
  const vulnerabilityCount = Array.isArray(node?.vulnerabilities) ? node.vulnerabilities.length : 0;
  const appCount = Array.isArray(node?.affectedApplications) ? node.affectedApplications.length : 0;

  if (severity === 'Critical') {
    return `Critical exposure with ${vulnerabilityCount} known issue${vulnerabilityCount === 1 ? '' : 's'} affecting ${appCount} application${appCount === 1 ? '' : 's'}.`;
  }

  if (severity === 'High') {
    return `High-risk dependency with known vulnerabilities affecting ${appCount} application${appCount === 1 ? '' : 's'}.`;
  }

  if (severity === 'Medium') {
    return 'Review recommended because this package sits above the safe threshold.';
  }

  return 'No critical issues detected, but keep this package under review.';
}

export default function PackageTable() {
  const [packages, setPackages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    let isMounted = true;

    async function fetchPriorities() {
      try {
        const response = await getPriorities();
        const flattened = flattenPriorities(response.data);

        const sorted = flattened
          .filter((node) => node && typeof node === 'object')
          .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))
          .slice(0, 10);

        if (isMounted) {
          setPackages(sorted);
        }
      } catch (requestError) {
        if (isMounted) {
          setError('Unable to load priority queue.');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    fetchPriorities();

    return () => {
      isMounted = false;
    };
  }, []);

  const rows = useMemo(() => {
    return packages.map((node) => {
      const severity = getSeverity(node);

      return {
        node,
        severity,
        explanation: getPlainEnglishExplanation(node, severity),
      };
    });
  }, [packages]);

  return (
    <section className="package-table">
      <div className="package-table__header">
        <h3>Top risks requiring attention</h3>
        <p>Readable findings sorted by exposure.</p>
      </div>

      {loading ? (
        <div className="package-table__state">Loading priority queue...</div>
      ) : error ? (
        <div className="package-table__state package-table__state--error">{error}</div>
      ) : (
        <div className="package-table__table-wrap">
          <table className="package-table__table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Package</th>
                <th>Finding</th>
                <th>Apps</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {rows.length > 0 ? (
                rows.map(({ node, severity, explanation }) => {
                  const expanded = expandedId === node.id;
                  const appCount = Array.isArray(node.affectedApplications) ? node.affectedApplications.length : 0;

                  return (
                    <Fragment key={node.id}>
                      <tr className={expanded ? 'package-table__row package-table__row--expanded' : 'package-table__row'}>
                        <td>
                          <span className={getSeverityClass(severity)}>{severity}</span>
                        </td>
                        <td>
                          <div className="package-table__package-name mono">{node.id}</div>
                          <div className="package-table__package-meta mono">{node.version}</div>
                        </td>
                        <td>
                          <p className="package-table__finding">{explanation}</p>
                        </td>
                        <td className="package-table__count mono">{appCount}</td>
                        <td>
                          <span className="package-table__status">{node.priority}</span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="package-table__expand"
                            onClick={() => setExpandedId(expanded ? null : node.id)}
                            aria-label={expanded ? 'Collapse finding' : 'Expand finding'}
                          >
                            <span className={expanded ? 'package-table__chevron package-table__chevron--open' : 'package-table__chevron'}>
                              ▸
                            </span>
                          </button>
                        </td>
                      </tr>

                      {expanded ? (
                        <tr className="package-table__details-row">
                          <td colSpan="6">
                            <div className="package-table__details">
                              <div>
                                <span className="package-table__details-label">License</span>
                                <div>{node.license || 'Unknown'}</div>
                              </div>

                              <div>
                                <span className="package-table__details-label">Risk score</span>
                                <div className="mono">{Number(node.riskScore ?? 0).toFixed(0)}</div>
                              </div>

                              <div>
                                <span className="package-table__details-label">Last updated</span>
                                <div className="mono">{node.lastUpdated || '--'}</div>
                              </div>

                              <div>
                                <span className="package-table__details-label">Affected applications</span>
                                <div className="mono">{appCount}</div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" className="package-table__empty">
                    No critical issues detected.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
