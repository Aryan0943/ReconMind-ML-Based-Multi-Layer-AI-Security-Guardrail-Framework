import React, { useEffect, useState } from 'react';
import Navbar from '../components/Navbar';
import { getPolicies, updatePolicy, getHealth } from '../services/api';
import { Settings as SettingsIcon, Save, Database, Shield, Sliders } from 'lucide-react';

export default function Settings() {
  const [policies, setPolicies] = useState({});
  const [health, setHealth] = useState(null);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const [polData, hData] = await Promise.all([getPolicies(), getHealth()]);
        setPolicies(polData.policies || {});
        setHealth(hData);
      } catch (e) {
        console.error('Failed to load settings:', e);
      }
    };
    load();
  }, []);

  const handleThresholdChange = (layer, val) => {
    setPolicies(prev => ({
      ...prev,
      [layer]: { ...prev[layer], threshold: parseFloat(val) }
    }));
  };

  const handleToggleEnable = (layer) => {
    setPolicies(prev => ({
      ...prev,
      [layer]: { ...prev[layer], enabled: !prev[layer]?.enabled }
    }));
  };

  const handleDefaultActionChange = (layer, act) => {
    setPolicies(prev => ({
      ...prev,
      [layer]: { ...prev[layer], default_action: act }
    }));
  };

  const handleSavePolicy = async (layer) => {
    setSaving(true);
    setStatusMsg('');
    try {
      await updatePolicy(layer, policies[layer]);
      setStatusMsg(`Successfully updated policies for ${layer} layer.`);
      setTimeout(() => setStatusMsg(''), 4000);
    } catch (e) {
      alert('Failed to update policy: ' + e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <Navbar title="Policies & System Settings" subtitle="Configure Guardrail Confidence Thresholds and Security Enforcement" />

      <div className="page-wrapper">
        {statusMsg && (
          <div style={{ padding: '12px 16px', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: 8, color: '#A7F3D0', marginBottom: '20px' }}>
            {statusMsg}
          </div>
        )}

        {/* System Environment Status Card */}
        <div className="card" style={{ marginBottom: '24px' }}>
          <div className="card-title">
            <span>System Infrastructure Health</span>
            <Database size={18} color="var(--accent-cyan)" />
          </div>
          <div className="card-subtitle">Database configuration and runtime status</div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
            <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Database Engine</span>
              <p style={{ fontWeight: 600, marginTop: '4px' }}>
                {health?.database?.connected ? 'MongoDB Live Daemon' : 'Local JSON File Store (Active Fallback)'}
              </p>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Database Name</span>
              <p style={{ fontWeight: 600, marginTop: '4px' }}>{health?.database?.db_name || 'reconmind'}</p>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>ML Engine Status</span>
              <p style={{ fontWeight: 600, marginTop: '4px', color: '#10B981' }}>
                {health?.ml_engine?.loaded ? 'Scikit-Learn Models Loaded' : 'Models Offline'}
              </p>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Backend Framework</span>
              <p style={{ fontWeight: 600, marginTop: '4px' }}>FastAPI (Asynchronous REST)</p>
            </div>
          </div>
        </div>

        {/* Layer Policy Configurations */}
        <div className="card">
          <div className="card-title">
            <span>Defense Layer Policies & Thresholds</span>
            <Sliders size={18} color="var(--accent-cyan)" />
          </div>
          <div className="card-subtitle">
            Fine-tune sensitivity thresholds and fallback enforcement actions for each interaction point.
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {['input', 'memory', 'retrieval', 'tool', 'output'].map((layerKey) => {
              const pol = policies[layerKey] || { enabled: true, threshold: 0.75, default_action: 'BLOCK' };
              return (
                <div 
                  key={layerKey}
                  style={{ 
                    padding: '16px 20px', 
                    background: 'var(--bg-secondary)', 
                    borderRadius: 'var(--radius-md)', 
                    border: '1px solid var(--border-color)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontSize: '1rem', fontWeight: 600, textTransform: 'capitalize' }}>
                        {layerKey} Defense
                      </span>
                      <span className={`badge ${pol.enabled ? 'badge-pass' : 'badge-block'}`}>
                        {pol.enabled ? 'ACTIVE' : 'BYPASSED'}
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: '10px' }}>
                      <button 
                        type="button"
                        className="btn btn-secondary" 
                        style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                        onClick={() => handleToggleEnable(layerKey)}
                      >
                        {pol.enabled ? 'Disable Layer' : 'Enable Layer'}
                      </button>
                      <button 
                        type="button"
                        className="btn btn-primary" 
                        style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                        onClick={() => handleSavePolicy(layerKey)}
                        disabled={saving}
                      >
                        <Save size={14} /> Save
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', alignItems: 'center' }}>
                    {/* Threshold slider */}
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--text-secondary)' }}>ML Threat Threshold</span>
                        <span style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{(pol.threshold * 100).toFixed(0)}%</span>
                      </div>
                      <input 
                        type="range" 
                        min="0.30" 
                        max="0.95" 
                        step="0.05"
                        value={pol.threshold}
                        onChange={(e) => handleThresholdChange(layerKey, e.target.value)}
                        style={{ width: '100%', accentColor: 'var(--accent-cyan)' }}
                      />
                    </div>

                    {/* Default action */}
                    <div>
                      <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                        Borderline / Default Action
                      </label>
                      <select 
                        className="form-select" 
                        value={pol.default_action || 'BLOCK'} 
                        onChange={(e) => handleDefaultActionChange(layerKey, e.target.value)}
                        style={{ padding: '6px 10px', fontSize: '0.85rem' }}
                      >
                        <option value="PASS">PASS</option>
                        <option value="SANITIZE">SANITIZE / QUARANTINE</option>
                        <option value="BLOCK">BLOCK</option>
                      </select>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
