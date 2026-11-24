import React from 'react';

export default function StatCard({ label, value, icon: Icon, color = 'var(--accent-cyan)', subtext }) {
  return (
    <div className="card stat-card">
      <div className="stat-header">
        <span className="stat-label">{label}</span>
        <div className="stat-icon" style={{ backgroundColor: `${color}15`, color }}>
          {Icon && <Icon size={20} />}
        </div>
      </div>
      <div className="stat-value">{value}</div>
      {subtext && <div className="stat-footer">{subtext}</div>}
    </div>
  );
}
