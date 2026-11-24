import React, { useEffect, useState } from 'react';
import Navbar from '../components/Navbar';
import DecisionBadge from '../components/DecisionBadge';
import ThreatBadge from '../components/ThreatBadge';
import { getSecurityLogs } from '../services/api';
import { Search, Filter, RefreshCw, FileText } from 'lucide-react';

export default function SecurityLogs() {
  const [logs, setLogs] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  
  // Filters
  const [layerFilter, setLayerFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await getSecurityLogs(100, 0, layerFilter || null, actionFilter || null);
      setLogs(data.logs || []);
      setTotalCount(data.count || 0);
    } catch (e) {
      console.error('Failed to load logs:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [layerFilter, actionFilter]);

  const filteredLogs = logs.filter((l) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      (l.event_id && l.event_id.toLowerCase().includes(term)) ||
      (l.input_preview && l.input_preview.toLowerCase().includes(term)) ||
      (l.reason && l.reason.toLowerCase().includes(term)) ||
      (l.category && l.category.toLowerCase().includes(term))
    );
  });

  return (
    <div>
      <Navbar title="Security Audit Logs" subtitle="Permanent Event Ledger of Inspection & Guardrail Enforcements" />

      <div className="page-wrapper">
        {/* Controls Card */}
        <div className="card" style={{ marginBottom: '24px' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', gap: '12px', flex: 1, minWidth: '300px' }}>
              <div style={{ position: 'relative', flex: 1 }}>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Search events by ID, content preview, or reason..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>

              <select className="form-select" style={{ width: '160px' }} value={layerFilter} onChange={(e) => setLayerFilter(e.target.value)}>
                <option value="">All Layers</option>
                <option value="input">Input</option>
                <option value="memory">Memory</option>
                <option value="retrieval">Retrieval</option>
                <option value="tool">Tool</option>
                <option value="output">Output</option>
              </select>

              <select className="form-select" style={{ width: '160px' }} value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
                <option value="">All Actions</option>
                <option value="PASS">PASS</option>
                <option value="SANITIZE">SANITIZE</option>
                <option value="BLOCK">BLOCK</option>
              </select>
            </div>

            <button className="btn btn-secondary" onClick={fetchLogs} disabled={loading}>
              <RefreshCw size={15} /> Refresh Logs
            </button>
          </div>
        </div>

        {/* Logs Table */}
        <div className="card">
          <div className="card-title">
            <span>Security Events ({filteredLogs.length})</span>
            <FileText size={18} color="var(--accent-cyan)" />
          </div>
          <div className="card-subtitle">Click any row to view complete event payload and decision details</div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp</th>
                  <th>Layer</th>
                  <th>Prediction</th>
                  <th>Category</th>
                  <th>Confidence</th>
                  <th>Action</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length > 0 ? (
                  filteredLogs.map((log) => (
                    <tr 
                      key={log.event_id} 
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSelectedEvent(log)}
                    >
                      <td className="font-mono" style={{ color: '#93C5FD' }}>{log.event_id}</td>
                      <td style={{ color: '#94A3B8' }}>{new Date(log.timestamp).toLocaleString()}</td>
                      <td style={{ textTransform: 'capitalize' }}>{log.layer}</td>
                      <td>
                        <span style={{ color: log.prediction === 'malicious' ? '#EF4444' : '#10B981', fontWeight: 600 }}>
                          {log.prediction?.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <ThreatBadge category={log.category} />
                      </td>
                      <td style={{ fontWeight: 600 }}>
                        {log.confidence !== undefined ? `${(log.confidence * 100).toFixed(1)}%` : 'N/A'}
                      </td>
                      <td>
                        <DecisionBadge action={log.action} />
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{log.latency_ms} ms</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="8" style={{ textAlign: 'center', padding: '24px', color: '#64748B' }}>
                      {loading ? 'Loading security logs...' : 'No security logs found matching filters.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Event Details Modal / Panel */}
        {selectedEvent && (
          <div style={{ marginTop: '24px' }} className="card">
            <div className="card-title">
              <span>Event Details: <code className="font-mono">{selectedEvent.event_id}</code></span>
              <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '0.75rem' }} onClick={() => setSelectedEvent(null)}>
                Close
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '12px' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Input Content Preview</span>
                <p style={{ padding: '10px', background: 'var(--bg-secondary)', borderRadius: 6, fontSize: '0.85rem', marginTop: '4px' }}>
                  {selectedEvent.input_preview}
                </p>
              </div>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Decision Rationale</span>
                <p style={{ padding: '10px', background: 'var(--bg-secondary)', borderRadius: 6, fontSize: '0.85rem', marginTop: '4px' }}>
                  {selectedEvent.reason}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
