import './RiskChart.css';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Cell,
} from 'recharts';

const SEVERITY_COLORS = {
  Critical: '#ff6b6b',
  High: '#f59e0b',
  Medium: '#5b27c2',
  Low: '#38bdf8',
};

function buildRiskData(graph) {
  const nodes = Array.isArray(graph) ? graph : [];

  const buckets = nodes.reduce(
    (accumulator, node) => {
      const score = Number(node?.riskScore ?? 0);

      if (score >= 85) {
        accumulator.Critical += 1;
      } else if (score >= 70) {
        accumulator.High += 1;
      } else if (score >= 50) {
        accumulator.Medium += 1;
      } else {
        accumulator.Low += 1;
      }

      return accumulator;
    },
    {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
    }
  );

  return [
    { name: 'Critical', value: buckets.Critical, color: SEVERITY_COLORS.Critical },
    { name: 'High', value: buckets.High, color: SEVERITY_COLORS.High },
    { name: 'Medium', value: buckets.Medium, color: SEVERITY_COLORS.Medium },
    { name: 'Low', value: buckets.Low, color: SEVERITY_COLORS.Low },
  ];
}

export default function RiskChart({ graph = [] }) {
  const riskData = buildRiskData(graph);
  const total = riskData.reduce((sum, item) => sum + item.value, 0);

  if (!total) {
    return (
      <section className="risk-chart risk-chart--empty">
        <div className="risk-chart__empty-state">
          <h3>Waiting for dependency data</h3>
          <p>
            The severity chart will render once the graph is available from the backend.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="risk-chart">
      <div className="risk-chart__meta">
        <div>
          <span className="risk-chart__label">Packages analyzed</span>
          <strong>{total}</strong>
        </div>

        <div className="risk-chart__legend">
          {riskData.map((entry) => (
            <span key={entry.name} className="risk-chart__legend-item">
              <span
                className="risk-chart__legend-dot"
                style={{ backgroundColor: entry.color }}
              />
              {entry.name}
            </span>
          ))}
        </div>
      </div>

      <div className="risk-chart__canvas">
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={riskData} barSize={44} margin={{ top: 8, right: 16, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="rgba(112, 126, 170, 0.12)" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#6f7480', fontSize: 12 }} />
            <YAxis axisLine={false} tickLine={false} tick={{ fill: '#6f7480', fontSize: 12 }} allowDecimals={false} />
            <Tooltip
              cursor={{ fill: 'rgba(91, 39, 194, 0.08)' }}
              contentStyle={{
                background: '#ffffff',
                border: '1px solid rgba(112, 126, 170, 0.16)',
                borderRadius: '14px',
                color: '#172033',
                boxShadow: '0 18px 30px rgba(35, 44, 78, 0.12)',
              }}
              labelStyle={{ color: '#6f7480' }}
            />
            <Bar dataKey="value" radius={[12, 12, 0, 0]} isAnimationActive animationDuration={900} animationEasing="ease-out">
              {riskData.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
