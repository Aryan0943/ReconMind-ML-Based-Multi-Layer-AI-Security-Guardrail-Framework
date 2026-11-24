import React, { useEffect, useState } from 'react';
import { getHealth } from '../services/api';
import { ShieldCheck, Database, Cpu } from 'lucide-react';

export default function Navbar({ title = 'Security Overview', subtitle = 'Multi-Layer AI Guardrail Protection' }) {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const data = await getHealth();
        setHealth(data);
      } catch (e) {
        setHealth({ status: 'offline', database: { mode: 'fallback' }, ml_engine: { loaded: false } });
      }
    };
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const isMongoConnected = Boolean(health?.database?.connected);
  const isFallback = Boolean(health?.database?.is_fallback || !isMongoConnected);
  const isMlOk = Boolean(health?.ml_engine?.loaded);

  return (
    <header className="navbar">
      <div className="navbar-title">
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>

      <div className="status-pills">
        <div 
          className="status-pill" 
          title={isMongoConnected ? "Connected to live MongoDB daemon" : "ATTENTION: Using local JSON file store (MongoDB offline)"}
          style={{ 
            borderColor: isMongoConnected ? 'rgba(16, 185, 129, 0.4)' : 'rgba(245, 158, 11, 0.5)',
            background: isMongoConnected ? 'rgba(16, 185, 129, 0.08)' : 'rgba(245, 158, 11, 0.1)'
          }}
        >
          <Database size={14} color={isMongoConnected ? '#10B981' : '#F59E0B'} />
          <span className={`status-dot ${isMongoConnected ? 'online' : 'warning'}`}></span>
          <span style={{ color: isMongoConnected ? '#A7F3D0' : '#FDE68A', fontWeight: 600 }}>
            {isMongoConnected ? 'MongoDB Live' : 'Storage: JSON Fallback (MongoDB Offline)'}
          </span>
        </div>

        <div className="status-pill" title="ML Inference Engine (Scikit-Learn)">
          <Cpu size={14} color={isMlOk ? '#10B981' : '#F59E0B'} />
          <span className={`status-dot ${isMlOk ? 'online' : 'warning'}`}></span>
          <span>{isMlOk ? 'ShieldLM Models' : 'Models Loading'}</span>
        </div>

        <div className="status-pill">
          <ShieldCheck size={14} color="#0EA5E9" />
          <span style={{ color: '#0EA5E9', fontWeight: 600 }}>5 Defense Layers</span>
        </div>
      </div>
    </header>
  );
}
