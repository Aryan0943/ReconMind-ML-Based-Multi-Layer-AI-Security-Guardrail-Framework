import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Scan, 
  Layers, 
  Bot,
  FileText, 
  Cpu, 
  Settings 
} from 'lucide-react';

export default function Sidebar() {
  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/scanner', label: 'Security Scanner', icon: Scan },
    { to: '/layers', label: '5-Layer Testing', icon: Layers },
    { to: '/agent', label: 'Agent Simulation', icon: Bot },
    { to: '/logs', label: 'Security Logs', icon: FileText },
    { to: '/evaluation', label: 'Model Evaluation', icon: Cpu },
    { to: '/settings', label: 'Policies & Settings', icon: Settings }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="logo-icon">
          <ShieldAlert size={20} />
        </div>
        <div className="logo-text">
          <h1>ReconMind</h1>
          <span>AI Guardrail Engine</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              end={item.to === '/'}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <p>B.Tech ML Project</p>
        <p style={{ marginTop: '4px', color: 'var(--accent-cyan)' }}>ReconMind v1.0.0</p>
      </div>
    </aside>
  );
}
