import React, { useEffect, useState } from 'react';
import Navbar from '../components/Navbar';
import StatCard from '../components/StatCard';
import DecisionBadge from '../components/DecisionBadge';
import ThreatBadge from '../components/ThreatBadge';
import { getDashboardStats, getRecentActivity } from '../services/api';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Filter, 
  Clock, 
  Activity,
  Layers
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, Legend 
} from 'recharts';

const PIE_COLORS = ['#EF4444', '#F59E0B', '#6366F1', '#EC4899', '#8B5CF6'];

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [activity, setActivity] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [s, a, h] = await Promise.all([getDashboardStats(), getRecentActivity(), import('../services/api').then(m => m.getHealth())]);
        setStats(s);
        setActivity(a.activity || []);
        setHealth(h);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 8000);
    return () => clearInterval(interval);
  }, []);

  const isMongoConnected = Boolean(health?.database?.connected);

  const layerData = stats ? [
    { name: 'Input', count: stats.layer_activity?.input || 0 },
    { name: 'Memory', count: stats.layer_activity?.memory || 0 },
    { name: 'Retrieval', count: stats.layer_activity?.retrieval || 0 },
    { name: 'Tool', count: stats.layer_activity?.tool || 0 },
    { name: 'Output', count: stats.layer_activity?.output || 0 },
  ] : [];

  const threatData = stats && stats.threat_distribution ? Object.entries(stats.threat_distribution).map(([key, val]) => ({
    name: key.replace(/_/g, ' '),
    value: val
  })) : [];

  return (
    <div>
      <Navbar title="Security Dashboard" subtitle="Live Monitoring & Multi-Layer AI Guardrail Telemetry" />
      
      <div className="page-wrapper">
        {/* Persistence Mode Notification Banner */}
        {!isMongoConnected && (
          <div style={{ 
            padding: '12px 18px', 
            marginBottom: '20px', 
            borderRadius: 'var(--radius-md)', 
            background: 'rgba(245, 158, 11, 0.08)', 
            border: '1px solid rgba(245, 158, 11, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.85rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="status-dot warning"></span>
              <span style={{ color: '#FDE68A', fontWeight: 600 }}>Active Storage: Local JSON File Fallback</span>
              <span style={{ color: '#94A3B8' }}>— MongoDB daemon is not connected; audit logs and memory are saved to local project files.</span>
            </div>
            <a href="/settings" style={{ color: '#0EA5E9', textDecoration: 'none', fontWeight: 600 }}>Configure Database &rarr;</a>
          </div>
        )}

        {/* Top Metric Cards */}
        <div className="grid-cols-4">
          <StatCard
            label="Total Requests Scanned"
            value={stats?.total_scanned ?? 0}
            icon={Activity}
            color="#0EA5E9"
            subtext="Across all 5 defense layers"
          />
          <StatCard
            label="Threats Detected"
            value={stats?.threats_detected ?? 0}
            icon={ShieldAlert}
            color="#F59E0B"
            subtext="Malicious interactions flagged"
          />
          <StatCard
            label="Requests Blocked"
            value={stats?.requests_blocked ?? 0}
            icon={ShieldX}
            color="#EF4444"
            subtext="Strict policy enforcements"
          />
          <StatCard
            label="Requests Sanitized"
            value={stats?.requests_sanitized ?? 0}
            icon={Filter}
            color="#10B981"
            subtext="Redacted & quarantined safely"
          />
        </div>

        {/* Charts Row */}
        <div className="grid-cols-2">
          {/* Layer-wise Activity */}
          <div className="card">
            <div className="card-title">
              <span>Layer-wise Activity</span>
              <Layers size={16} color="var(--accent-cyan)" />
            </div>
            <div className="card-subtitle">Volume of requests processed across each defense layer</div>
            
            <div style={{ height: 260, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={layerData}>
                  <XAxis dataKey="name" stroke="#64748B" fontSize={12} tickLine={false} />
                  <YAxis stroke="#64748B" fontSize={12} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0D1527', borderColor: '#1E293B', borderRadius: 8, color: '#F8FAFC' }}
                    cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                  />
                  <Bar dataKey="count" fill="#0EA5E9" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Category Distribution */}
          <div className="card">
            <div className="card-title">
              <span>Threat Category Distribution</span>
              <ShieldAlert size={16} color="#F59E0B" />
            </div>
            <div className="card-subtitle">Breakdown of identified prompt injections and vulnerabilities</div>

            <div style={{ height: 260, width: '100%' }}>
              {threatData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      innerRadius={45}
                      paddingAngle={4}
                    >
                      {threatData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#0D1527', borderColor: '#1E293B', borderRadius: 8 }} />
                    <Legend wrapperStyle={{ fontSize: '0.8rem', paddingTop: '10px' }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: '#64748B', fontSize: '0.9rem' }}>
                  No threats detected yet. Run security scans to view distribution.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Recent Events Timeline Table */}
        <div className="card">
          <div className="card-title">
            <span>Recent Security Events</span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Avg Latency: <strong style={{ color: 'var(--accent-cyan)' }}>{stats?.avg_latency_ms || 0} ms</strong>
            </span>
          </div>
          <div className="card-subtitle">Real-time audit log of security decisions executed by DefenseManager</div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp</th>
                  <th>Layer</th>
                  <th>Input Preview</th>
                  <th>Category</th>
                  <th>Confidence</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {activity.length > 0 ? (
                  activity.map((item) => (
                    <tr key={item.event_id}>
                      <td className="font-mono" style={{ color: '#93C5FD' }}>{item.event_id}</td>
                      <td style={{ color: '#94A3B8' }}>{new Date(item.timestamp).toLocaleTimeString()}</td>
                      <td>
                        <span style={{ textTransform: 'capitalize', fontWeight: 500 }}>{item.layer}</span>
                      </td>
                      <td style={{ maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {item.input_preview}
                      </td>
                      <td>
                        <ThreatBadge category={item.category} />
                      </td>
                      <td>
                        <span style={{ fontWeight: 600 }}>{(item.confidence * 100).toFixed(1)}%</span>
                      </td>
                      <td>
                        <DecisionBadge action={item.action} />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', color: '#64748B', padding: '24px' }}>
                      No events recorded yet. Try scanning a prompt in Security Scanner or Layer Testing!
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
