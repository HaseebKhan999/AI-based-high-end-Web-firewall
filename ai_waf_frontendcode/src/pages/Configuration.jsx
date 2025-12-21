import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { FiSettings, FiSave, FiRefreshCw } from 'react-icons/fi';
import './Configuration.css';

const Configuration = () => {
  const [config, setConfig] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);
  const [editedConfig, setEditedConfig] = useState({});

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getConfig();
      const configData = response.data.data || {};
      setConfig(configData);
      setEditedConfig(configData);
      setError(null);
    } catch (err) {
      setError('Failed to load configuration');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (key, value) => {
    setEditedConfig({
      ...editedConfig,
      [key]: value
    });
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      await adminAPI.updateConfig(editedConfig);
      setConfig(editedConfig);
      alert('Configuration updated successfully!');
    } catch (err) {
      alert('Failed to update configuration: ' + (err.response?.data?.error || err.message));
    } finally {
      setSaving(false);
    }
  };

  const hasChanges = JSON.stringify(config) !== JSON.stringify(editedConfig);

  const configFields = [
    {
      key: 'threat_threshold',
      label: 'Threat Threshold',
      type: 'number',
      min: 0,
      max: 1,
      step: 0.1,
      description: 'Requests with threat score above this value will be blocked (0.0 - 1.0)'
    },
    {
      key: 'enable_blocking',
      label: 'Enable Blocking',
      type: 'select',
      options: ['true', 'false'],
      description: 'Enable or disable request blocking'
    },
    {
      key: 'enable_logging',
      label: 'Enable Logging',
      type: 'select',
      options: ['true', 'false'],
      description: 'Enable or disable request logging'
    },
    {
      key: 'rate_limit_enabled',
      label: 'Rate Limiting Enabled',
      type: 'select',
      options: ['true', 'false'],
      description: 'Enable or disable rate limiting'
    },
    {
      key: 'rate_limit_requests',
      label: 'Rate Limit Requests',
      type: 'number',
      min: 1,
      description: 'Maximum number of requests per time window'
    },
    {
      key: 'rate_limit_window',
      label: 'Rate Limit Window (seconds)',
      type: 'number',
      min: 1,
      description: 'Time window for rate limiting in seconds'
    },
    {
      key: 'log_retention_days',
      label: 'Log Retention (days)',
      type: 'number',
      min: 1,
      description: 'Number of days to retain logs'
    }
  ];

  return (
    <div className="configuration-page">
      <div className="config-header">
        <div className="config-title-section">
          <FiSettings className="config-icon" />
          <div>
            <h2>WAF Configuration</h2>
            <p className="config-subtitle">Manage system settings and thresholds</p>
          </div>
        </div>
        <div className="config-actions">
          <button onClick={fetchConfig} className="refresh-btn">
            <FiRefreshCw /> Refresh
          </button>
          <button 
            onClick={handleSave} 
            disabled={!hasChanges || saving}
            className="save-btn"
          >
            <FiSave /> {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading configuration...</div>
      ) : error ? (
        <div className="error">Error: {error}</div>
      ) : (
        <div className="config-form-container">
          <div className="config-form">
            {configFields.map((field) => (
              <div key={field.key} className="config-field">
                <label className="config-field-label">
                  {field.label}
                  {field.description && (
                    <span className="config-field-hint">{field.description}</span>
                  )}
                </label>
                {field.type === 'select' ? (
                  <select
                    value={editedConfig[field.key] || ''}
                    onChange={(e) => handleChange(field.key, e.target.value)}
                    className="config-input"
                  >
                    {field.options.map(option => (
                      <option key={option} value={option}>{option}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={field.type}
                    value={editedConfig[field.key] || ''}
                    onChange={(e) => handleChange(field.key, e.target.value)}
                    min={field.min}
                    max={field.max}
                    step={field.step}
                    className="config-input"
                  />
                )}
                {config[field.key] !== editedConfig[field.key] && (
                  <span className="config-change-indicator">Modified</span>
                )}
              </div>
            ))}
          </div>

          {hasChanges && (
            <div className="config-warning">
              <p>You have unsaved changes. Click "Save Changes" to apply them.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Configuration;

