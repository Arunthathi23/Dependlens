import './StatCard.css';

export default function StatCard({ title, value, tone = 'violet', icon = '•' }) {
  return (
    <section className={`stat-card stat-card--${tone}`}>
      <div className="stat-card__icon" aria-hidden="true">
        {icon}
      </div>
      <p className="stat-card__label">{title}</p>
      <p className="stat-card__value">{value}</p>
    </section>
  );
}
