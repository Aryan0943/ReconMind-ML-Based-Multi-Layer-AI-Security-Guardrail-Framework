import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import SecurityScanner from './pages/SecurityScanner';
import LayerTesting from './pages/LayerTesting';
import AgentSimulation from './pages/AgentSimulation';
import SecurityLogs from './pages/SecurityLogs';
import ModelEvaluation from './pages/ModelEvaluation';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-container">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scanner" element={<SecurityScanner />} />
            <Route path="/layers" element={<LayerTesting />} />
            <Route path="/agent" element={<AgentSimulation />} />
            <Route path="/logs" element={<SecurityLogs />} />
            <Route path="/evaluation" element={<ModelEvaluation />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
