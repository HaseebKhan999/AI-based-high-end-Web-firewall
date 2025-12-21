import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import TrafficLogs from './pages/TrafficLogs';
import AttackLogs from './pages/AttackLogs';
import Whitelist from './pages/Whitelist';
import Blacklist from './pages/Blacklist';
import Configuration from './pages/Configuration';
import MLModels from './pages/MLModels';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/traffic-logs" element={<TrafficLogs />} />
          <Route path="/attack-logs" element={<AttackLogs />} />
          <Route path="/whitelist" element={<Whitelist />} />
          <Route path="/blacklist" element={<Blacklist />} />
          <Route path="/configuration" element={<Configuration />} />
          <Route path="/ml-models" element={<MLModels />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;

