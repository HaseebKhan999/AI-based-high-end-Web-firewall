import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { FiRefreshCw, FiShield, FiAlertTriangle } from 'react-icons/fi';
import './AttackLogs.css';

const AttackLogs = () => {
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAttacks();
    const interval = setInterval(fetchAttacks, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchAttacks = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getAttacks(100);
      setAttacks(response.data.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load attack logs');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return formatDateGMT5(dateString);
  };

  const getAttackTypeColor = (attackType) => {
    const colors = {
      'SQL Injection': '#ef4444',
      'XSS': '#f59e0b',
      'Command Injection': '#dc2626',
      'Path Traversal': '#ea580c',
      'Anomaly': '#8b5cf6',
    };
    return colors[attackType] || '#64748b';
  };

  return (
    <div className="attack-logs">
      <div className="attacks-header">
        <div className="attacks-title-section">
          <FiShield className="attacks-icon" />
          <div>
            <h2>Attack Logs</h2>
            <p className="attacks-subtitle">Blocked requests and detected threats</p>
          </div>
        </div>
        <button onClick={fetchAttacks} className="refresh-btn">
          <FiRefreshCw /> Refresh
        </button>
      </div>

      {loading && attacks.length === 0 ? (
        <div className="loading">Loading attack logs...</div>
      ) : error ? (
        <div className="error">Error: {error}</div>
      ) : attacks.length === 0 ? (
        <div className="no-attacks">
          <FiShield className="no-attacks-icon" />
          <h3>No Attacks Detected</h3>
          <p>All requests are currently being allowed. The system is secure.</p>
        </div>
      ) : (
        <div className="attacks-grid">
          {attacks.map((attack) => (
            <div key={attack.id} className="attack-card">
              <div className="attack-card-header">
                <div className="attack-type-badge" style={{ 
                  backgroundColor: `${getAttackTypeColor(attack.attack_type)}20`,
                  color: getAttackTypeColor(attack.attack_type)
                }}>
                  <FiAlertTriangle />
                  {attack.attack_type || 'Unknown Attack'}
                </div>
                <div className="threat-score-badge" style={{
                  backgroundColor: attack.threat_score >= 0.7 ? '#fee2e2' : '#fef3c7',
                  color: attack.threat_score >= 0.7 ? '#991b1b' : '#92400e'
                }}>
                  Threat: {(attack.threat_score || 0).toFixed(2)}
                </div>
              </div>
              <div className="attack-card-body">
                <div className="attack-info-item">
                  <span className="attack-info-label">IP Address:</span>
                  <span className="attack-info-value ip-address">{attack.ip_address}</span>
                </div>
                <div className="attack-info-item">
                  <span className="attack-info-label">Method:</span>
                  <span className={`method-badge method-${attack.method?.toLowerCase()}`}>
                    {attack.method}
                  </span>
                </div>
                <div className="attack-info-item">
                  <span className="attack-info-label">URL:</span>
                  <span className="attack-info-value url-text" title={attack.url}>
                    {attack.url}
                  </span>
                </div>
                <div className="attack-info-item">
                  <span className="attack-info-label">Timestamp:</span>
                  <span className="attack-info-value">{formatDate(attack.timestamp)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AttackLogs;

